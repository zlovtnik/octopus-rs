//! Coordinator HTTP contracts and scoped DQ service boundary.
use crate::{config::PublicStatsConfig, dq::{self,DqError,DqPrincipal}, dq_runtime::{DqStore,artifacts::DqArtifacts},observability::{iso,Metrics}};
use axum::{body::{to_bytes,Body}, extract::{MatchedPath,Query,Request,State}, http::{HeaderMap,StatusCode},middleware::{self,Next},response::{IntoResponse,Response},routing::{get,post},Json,Router};
use chrono::Utc;
use futures_util::future::BoxFuture;
use opentelemetry::{global,propagation::Extractor};
use serde_json::{json,Value};
use std::{collections::{BTreeSet,HashMap},sync::Arc,time::Duration};
use subtle::ConstantTimeEq;
use tracing::{Instrument,Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub type Check=Arc<dyn Fn()->BoxFuture<'static,bool>+Send+Sync>;
#[derive(Clone)]
pub struct HealthChecks {pub database:Check,pub processors:Check,pub dq:Check,pub timeout:Duration}
#[derive(Clone)]
pub struct DqHttp {pub store:DqStore,pub artifacts:DqArtifacts,pub control_token:String}
#[derive(Clone)]
pub struct HttpState {pub health:HealthChecks,pub metrics:Metrics,pub public_stats:PublicStatsConfig,pub dq:Option<DqHttp>}

pub fn router(state:HttpState)->Router {
    let mut app=Router::new().route("/live",get(live))
        .route("/ready",get(ready)).route("/health",get(ready)).route("/actuator/health",get(ready))
        .route("/metrics",get(metrics)).route("/actuator/prometheus",get(metrics))
        .route("/internal/metrics/live",get(live_metrics));
    if state.public_stats.enabled {app=app.route("/public/stats",get(public_stats).options(public_options));}
    if state.dq.is_some() {
        const ROOT:&str="/internal/dq/v1";
        for path in ["/invocations/:key","/processors","/processor-versions/:processor/:version","/runs/:run","/dispatches","/artifacts/:artifact"] {app=app.route(&format!("{ROOT}{path}"),get(dq_request));}
        for path in ["/processor-versions","/runs","/runs/:run/cancel","/runs/:run/replay","/receipts","/workers/:worker/heartbeat","/runs/:run/attempts/reserve","/attempts/:attempt/accepted","/attempts/:attempt/renew","/artifacts/:artifact/access"] {app=app.route(&format!("{ROOT}{path}"),post(dq_request));}
    }
    app.with_state(state).layer(middleware::from_fn(trace_request))
}
async fn live()->Json<Value>{Json(json!({"status":"UP"}))}
async fn checked(check:Check,timeout:Duration)->bool {tokio::time::timeout(timeout,check()).await.unwrap_or(false)}
async fn ready(State(state):State<HttpState>)->Response {
    let h=state.health;let(db,processors,dq)=tokio::join!(checked(h.database,h.timeout),checked(h.processors,h.timeout),checked(h.dq,h.timeout));
    let up=|b|if b{"UP"}else{"DOWN"};
    (if db&&processors&&dq{StatusCode::OK}else{StatusCode::SERVICE_UNAVAILABLE},Json(json!({"status":up(db&&processors&&dq),"components":{"postgres":{"status":up(db)},"processors":{"status":up(processors)},"dq":{"status":up(dq)}}}))).into_response()
}
async fn metrics(State(state):State<HttpState>)->Response {
    match state.metrics.scrape(){Ok(body)=>([("content-type","text/plain; version=0.0.4; charset=utf-8")],body).into_response(),Err(_)=>StatusCode::SERVICE_UNAVAILABLE.into_response()}
}
async fn live_metrics(State(state):State<HttpState>)->Response {let now=Utc::now();([( "cache-control","no-store")],Json(json!({"asOf":iso(now),"liveStrip":state.metrics.live(now)}))).into_response()}
fn cors(mut response:Response,headers:&HeaderMap,config:&PublicStatsConfig)->Response {
    response.headers_mut().insert("vary","Origin".parse().expect("static header"));
    if let Some(origin)=headers.get("origin").filter(|h|h.to_str().is_ok_and(|s|config.allowed_origins.iter().any(|o|o==s))){
        response.headers_mut().insert("access-control-allow-origin",origin.clone());
        response.headers_mut().insert("access-control-allow-methods","GET, OPTIONS".parse().expect("static header"));
        response.headers_mut().insert("access-control-allow-headers","Content-Type".parse().expect("static header"));
    }response
}
async fn public_stats(State(state):State<HttpState>,headers:HeaderMap)->Response {cors(([("cache-control","no-store")],Json(state.metrics.public_snapshot(Utc::now()))).into_response(),&headers,&state.public_stats)}
async fn public_options(State(state):State<HttpState>,headers:HeaderMap)->Response {cors(StatusCode::NO_CONTENT.into_response(),&headers,&state.public_stats)}

fn error(status:u16,code:&str)->DqError{DqError{status,code:code.into()}}
fn principal(headers:&HeaderMap,token:&str)->Result<DqPrincipal,DqError>{
    let supplied=headers.get("authorization").map(|h|h.as_bytes()).unwrap_or_default();
    let expected=format!("Bearer {token}");
    if crate::util::java_is_blank(token)||!bool::from(supplied.ct_eq(expected.as_bytes())){return Err(error(401,"service_auth_required"));}
    let Some(actor)=headers.get("x-dq-actor")else{return Ok(DqPrincipal::internal())};
    let actor=actor.to_str().map_err(|_|error(403,"invalid_actor"))?;
    if !dq::hash(actor){return Err(error(403,"invalid_actor"));}
    let list=|key:&str|headers.get(key).and_then(|h|h.to_str().ok()).unwrap_or("").split(',').map(str::trim).filter(|s|!s.is_empty()).map(String::from).collect::<BTreeSet<_>>();
    let roles=list("x-dq-roles");let scopes=list("x-dq-scopes");
    if roles.contains("service")||scopes.is_empty(){return Err(error(403,"invalid_principal"));}
    Ok(DqPrincipal{actor:actor.into(),roles,scopes})
}
async fn body(body:Body,maximum:usize)->Result<Value,DqError>{let bytes=to_bytes(body,maximum).await.map_err(|_|error(413,"record_too_large"))?;serde_json::from_slice(&bytes).map_err(|_|error(400,"invalid_json"))}
fn service(p:&DqPrincipal)->Result<(),DqError>{p.require_role(&["service".into()].into())}
fn scope(query:&HashMap<String,String>,control:&DqHttp)->Result<(),DqError>{
    if query.get("installation_id")!=Some(&control.store.settings.installation_id)||query.get("namespace")!=Some(&control.store.settings.namespace){Err(error(403,"forbidden_installation"))}else{Ok(())}
}
async fn dq_request(State(state):State<HttpState>,request:Request)->Response {
    let result=execute_dq(state.dq.as_ref().expect("DQ routes require resources"),request).await;
    match result {Ok((status,value))=>(status,Json(value)).into_response(),Err(e)=>(StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),Json(json!({"error":e.code}))).into_response()}
}
async fn execute_dq(control:&DqHttp,request:Request)->Result<(StatusCode,Value),DqError>{
    let p=principal(request.headers(),&control.control_token)?;
    let query=Query::<HashMap<String,String>>::try_from_uri(request.uri()).map_err(|_|error(400,"invalid_query"))?.0;
    let path=request.uri().path().trim_start_matches("/internal/dq/v1/").to_string();
    let parts=path.split('/').collect::<Vec<_>>();let method=request.method().clone();
    let store=&control.store;
    let mut status=StatusCode::OK;
    let value=match (method.as_str(),parts.as_slice()) {
        ("GET",["invocations",key])=>{scope(&query,control)?;store.invocation(&p,key).await?},
        ("GET",["processors"])=>{scope(&query,control)?;store.catalog(&p).await?},
        ("POST",["processor-versions"])=>{status=StatusCode::CREATED;store.register(&p,&body(request.into_body(),65536).await?).await?},
        ("GET",["processor-versions",processor,version])=>{scope(&query,control)?;store.manifest(&p,processor,version).await?},
        ("POST",["runs"])=>{p.require_role(&["operator".into(),"admin".into(),"automation".into()].into())?;status=StatusCode::ACCEPTED;store.admit(&p,&body(request.into_body(),65536).await?).await?},
        ("GET",["runs",run])=>{scope(&query,control)?;store.get_run(&p,run).await?},
        ("POST",["runs",run,"cancel"])=>{let v=body(request.into_body(),65536).await?;dq::scoped(&p,&v,&store.settings)?;store.cancel(&p,run).await?},
        ("POST",["runs",run,"replay"])=>{let v=body(request.into_body(),65536).await?;dq::scoped(&p,&v,&store.settings)?;status=StatusCode::ACCEPTED;store.replay(&p,run,&v).await?},
        ("POST",["receipts"])=>{service(&p)?;store.receive_receipt(&body(request.into_body(),71680).await?).await?},
        ("POST",["workers",worker,"heartbeat"])=>{service(&p)?;let v=body(request.into_body(),65536).await?;if dq::text(&v,"worker_instance_id")?!=*worker{return Err(error(400,"worker_identity_mismatch"));}store.heartbeat(&v).await?},
        ("GET",["dispatches"])=>{service(&p)?;scope(&query,control)?;let limit=query.get("limit").map(|v|v.parse::<i32>().ok().filter(|n|(1..=100).contains(n)).ok_or_else(||error(400,"invalid_dispatch_limit"))).transpose()?.unwrap_or(32);store.dispatches(limit).await?},
        ("POST",["runs",run,"attempts","reserve"])=>{service(&p)?;store.reserve(run,&body(request.into_body(),65536).await?).await?},
        ("POST",["attempts",attempt,"accepted"])=>{service(&p)?;store.accepted(attempt,&body(request.into_body(),65536).await?).await?},
        ("POST",["attempts",attempt,"renew"])=>{service(&p)?;store.renew(attempt,&body(request.into_body(),65536).await?).await?},
        ("GET",["artifacts",artifact])=>{scope(&query,control)?;store.artifact(&p,artifact,false).await?},
        ("POST",["artifacts",artifact,"access"])=>{let v=body(request.into_body(),65536).await?;dq::scoped(&p,&v,&store.settings)?;control.artifacts.authorized_access(&store.artifact(&p,artifact,true).await?).await?},
        _=>return Err(error(404,"not_found")),
    };Ok((status,value))
}
struct HeaderExtractor<'a>(&'a HeaderMap);
impl Extractor for HeaderExtractor<'_> {
    fn get(&self,key:&str)->Option<&str>{self.0.get(key)?.to_str().ok()}
    fn keys(&self)->Vec<&str>{self.0.keys().map(|k|k.as_str()).collect()}
}
async fn trace_request(request:Request,next:Next)->Response {
    if ["/live","/metrics","/actuator/prometheus"].contains(&request.uri().path()){return next.run(request).await;}
    let route=request.extensions().get::<MatchedPath>().map(|p|p.as_str()).unwrap_or("unmatched");
    let span=tracing::info_span!("http.request",otel.kind="server",http.request.method=%request.method(),http.route=route,http.response.status_code=tracing::field::Empty);
    let parent=global::get_text_map_propagator(|p|p.extract(&HeaderExtractor(request.headers())));
    let _=span.set_parent(parent);
    async move{let response=next.run(request).await;Span::current().record("http.response.status_code",response.status().as_u16());response}.instrument(span).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn service_auth_and_forwarded_principal_remain_distinct(){
        let mut headers=HeaderMap::new();assert_eq!(principal(&headers,"secret").unwrap_err().status,401);
        headers.insert("authorization","Bearer secret".parse().unwrap());assert_eq!(principal(&headers,"secret").unwrap(),DqPrincipal::internal());
        headers.insert("x-dq-actor","invalid".parse().unwrap());assert_eq!(principal(&headers,"secret").unwrap_err().code,"invalid_actor");
        headers.insert("x-dq-actor","a".repeat(64).parse().unwrap());headers.insert("x-dq-scopes","wireless".parse().unwrap());headers.insert("x-dq-roles","service".parse().unwrap());assert_eq!(principal(&headers,"secret").unwrap_err().code,"invalid_principal");
        headers.insert("x-dq-roles","viewer, operator".parse().unwrap());let user=principal(&headers,"secret").unwrap();assert!(user.roles.contains("operator"));assert!(service(&user).is_err());
        assert!(principal(&headers,"").is_err());
    }
    #[tokio::test]
    async fn body_limits_and_json_errors_have_contract_statuses(){assert_eq!(body(Body::from("12345"),4).await.unwrap_err().status,413);assert_eq!(body(Body::from("invalid"),100).await.unwrap_err().code,"invalid_json");assert_eq!(body(Body::from("{}"),2).await.unwrap(),json!({}));}
    #[tokio::test]
    async fn readiness_checks_run_concurrently_and_bound_stalls(){let stalled:Check=Arc::new(||Box::pin(std::future::pending()));assert!(!checked(stalled,Duration::from_millis(1)).await);}
}
