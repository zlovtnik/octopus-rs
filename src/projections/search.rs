use super::{wireless::delete_document,ProjectionError,ProjectionStore};
use crate::{postgres::PgTransaction,util::{java_is_blank,java_trim,sha256_hex,utf16_length}};
use chrono::{DateTime,Utc};
use md5::{Digest,Md5};
use serde_json::{json,Value};
use std::collections::{BTreeMap,BTreeSet};
#[path="search_sql.rs"]mod sql;

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum SearchKind{Event,Device,Behaviour,Sequence,ProxyEvent,ProxyFlow,ProxyBlockedHostWindow,DeviceProfile,ApProfile,IdentitySummary,ObservationWindow}
impl SearchKind{
    pub const NON_PROXY:[Self;8]=[Self::Event,Self::Device,Self::Behaviour,Self::Sequence,Self::DeviceProfile,Self::ApProfile,Self::IdentitySummary,Self::ObservationWindow];
    pub fn source_table(self)->&'static str{match self{Self::Event=>"wireless_frames",Self::Device=>"devices",Self::Behaviour=>"behaviour_snapshots",Self::Sequence=>"frame_sequences",Self::ProxyEvent|Self::ProxyBlockedHostWindow=>"proxy_events",Self::ProxyFlow=>"proxy_flows",Self::DeviceProfile|Self::ApProfile=>"wireless_topology_nodes",Self::IdentitySummary=>"identity_clusters",Self::ObservationWindow=>"wireless_observation_summaries"}}
    pub fn source_kind(self)->&'static str{match self{Self::Event=>"event",Self::Device=>"device",Self::Behaviour=>"behaviour_window",Self::Sequence=>"frame_sequence",Self::ProxyEvent=>"proxy_event",Self::ProxyFlow=>"proxy_flow",Self::ProxyBlockedHostWindow=>"proxy_blocked_host_window",Self::DeviceProfile=>"device_profile",Self::ApProfile=>"ap_profile",Self::IdentitySummary=>"identity_summary",Self::ObservationWindow=>"observation_window"}}
    pub fn embedding_kind(self)->&'static str{match self{Self::Event|Self::ProxyEvent|Self::ProxyFlow|Self::ProxyBlockedHostWindow=>"event",Self::Device|Self::DeviceProfile|Self::ApProfile|Self::IdentitySummary=>"device",Self::Behaviour|Self::ObservationWindow=>"behaviour",Self::Sequence=>"sequence"}}
    pub fn compact(self)->bool{matches!(self,Self::DeviceProfile|Self::ApProfile|Self::IdentitySummary|Self::ObservationWindow)}
    pub fn proxy(self)->bool{matches!(self,Self::ProxyEvent|Self::ProxyFlow|Self::ProxyBlockedHostWindow)}
}
#[derive(Clone,Debug)]
pub struct SearchSource{
    pub kind:SearchKind,pub key:String,pub source_mac:Option<String>,pub location_id:Option<String>,pub sensor_id:Option<String>,pub observed_at:DateTime<Utc>,
    pub bssid:Option<String>,pub ssid:Option<String>,pub frame_subtype:Option<String>,pub security_flags:i32,pub handshake:bool,pub search_text:String,pub detail:Value,
    pub host:Option<String>,pub proxy_device_id:Option<String>,pub proxy_event_type:Option<String>,pub blocked:Option<bool>,pub classification:Option<String>,
    pub window_start:Option<DateTime<Utc>>,pub window_end:Option<DateTime<Utc>>,pub evidence_revision:Option<i64>,pub template_version:String,pub normalization_version:String,pub input_revision:String,
}
impl SearchSource{
    pub fn new(kind:SearchKind,key:String,observed_at:DateTime<Utc>,search_text:String,detail:Value)->Self{
        Self{kind,key,source_mac:None,location_id:None,sensor_id:None,observed_at,bssid:None,ssid:None,frame_subtype:None,security_flags:0,handshake:false,search_text,detail,host:None,proxy_device_id:None,proxy_event_type:None,blocked:None,classification:None,window_start:None,window_end:None,evidence_revision:None,template_version:"legacy_unknown".into(),normalization_version:"legacy_unknown".into(),input_revision:"legacy_unknown".into()}
    }
}
#[derive(Clone,Debug)]
pub struct PreparedDocument{pub source:SearchSource,pub document_id:String,pub source_version:i64,pub normalized_text:String,pub normalized_sha256:String,pub title:Option<String>,pub tokens:Vec<(String,f64,i32)>,pub tags:Vec<(String,String)>}

pub fn name_uuid(value:&str)->String{
    let mut bytes:[u8;16]=Md5::digest(value.as_bytes()).into();bytes[6]=(bytes[6]&0x0f)|0x30;bytes[8]=(bytes[8]&0x3f)|0x80;uuid::Uuid::from_bytes(bytes).to_string()
}
pub fn tokenize(normalized:&str)->Vec<String>{
    static TOKEN:std::sync::OnceLock<regex::Regex>=std::sync::OnceLock::new();
    TOKEN.get_or_init(||regex::Regex::new("[a-z0-9][a-z0-9:_./-]{0,190}").expect("constant token pattern")).find_iter(normalized).map(|m|m.as_str().into()).collect()
}
pub fn prepare_source(source:SearchSource)->Result<PreparedDocument,ProjectionError>{
    let normalized_text=crate::compatibility::normalize_search_text(&source.search_text)
        .map_err(|_|ProjectionError::Invalid("Unicode NFKC normalization is unavailable"))?;
    if java_is_blank(&source.key){return Err(ProjectionError::Invalid("search document source key must not be blank"));}
    if normalized_text.is_empty(){return Err(ProjectionError::Invalid("search document has no searchable text"));}
    let checksum=sha256_hex(normalized_text.as_bytes());
    let document_id=if source.kind.compact(){name_uuid(&format!("{}:{}{}:{}",utf16_length(source.kind.source_kind()),source.kind.source_kind(),utf16_length(&source.key),source.key))}else{name_uuid(&format!("{}:{}:{checksum}",source.kind.source_table(),source.key))};
    let mut counts=BTreeMap::<String,i32>::new();for token in tokenize(&normalized_text){*counts.entry(token).or_default()+=1;}
    let total=counts.values().sum::<i32>().max(1);let tokens=counts.into_iter().map(|(token,count)|(token,f64::from(count)/f64::from(total),count)).collect();
    let mut tags=BTreeSet::new();
    for (kind,value) in [("source_mac",source.source_mac.as_ref()),("location_id",source.location_id.as_ref()),("sensor_id",source.sensor_id.as_ref()),("bssid",source.bssid.as_ref()),("ssid",source.ssid.as_ref()),("frame_subtype",source.frame_subtype.as_ref()),("host",source.host.as_ref().filter(|v|utf16_length(v)<=255)),("proxy_device_id",source.proxy_device_id.as_ref()),("proxy_event_type",source.proxy_event_type.as_ref()),("classification",source.classification.as_ref())]{if let Some(value)=value{tags.insert((kind.into(),value.clone()));}}
    if let Some(blocked)=source.blocked{tags.insert(("blocked".into(),blocked.to_string()));}
    let mut seen=BTreeSet::new();let title=[source.proxy_event_type.as_deref(),source.host.as_deref(),source.frame_subtype.as_deref(),source.ssid.as_deref(),source.source_mac.as_deref()].into_iter().flatten().map(java_trim).filter(|v|!v.is_empty()).filter(|v|seen.insert(*v)).collect::<Vec<_>>().join(" ");
    let title=(!title.is_empty()).then(||String::from_utf16_lossy(&title.encode_utf16().take(512).collect::<Vec<_>>()));
    Ok(PreparedDocument{source,document_id,source_version:i64::from_str_radix(&checksum[..15],16).expect("fifteen SHA digits fit i64"),normalized_text,normalized_sha256:checksum,title,tokens,tags:tags.into_iter().collect()})
}

pub async fn persist_document(tx:&mut PgTransaction,document:&PreparedDocument,fenced_proxy:bool)->Result<(),ProjectionError>{
    let s=&document.source;
    if s.kind.proxy()&&!fenced_proxy{return Err(ProjectionError::Invalid("proxy documents require fenced proxy-search-preparer"));}
    if s.kind==SearchKind::ObservationWindow&&tx.query("SELECT 1 FROM atheros_search.wireless_observation_summaries WHERE summary_id=$1::text::uuid AND expires_at>CURRENT_TIMESTAMP FOR UPDATE",&[&s.key]).await?.is_empty(){return Ok(());}
    tx.query("SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array($1::text,$2::text)::text,0)) IS NULL",&[&s.kind.source_table(),&s.key]).await?;
    if s.kind.compact(){let rows=tx.query("SELECT document_id::text FROM atheros_search.search_documents WHERE document_id=$1::text::uuid AND normalized_sha256<>$2 FOR UPDATE",&[&document.document_id,&document.normalized_sha256]).await?;if !rows.is_empty(){delete_document(tx,&document.document_id).await?;}}
    let superseded=tx.query("UPDATE atheros_search.search_documents SET status='superseded',updated_at=CURRENT_TIMESTAMP WHERE source_table=$1 AND source_key=$2 AND document_id<>$3::text::uuid AND status='active' RETURNING document_id::text",&[&s.kind.source_table(),&s.key,&document.document_id]).await?.into_iter().map(|r|r.get::<_,String>(0)).collect::<Vec<_>>();
    if !superseded.is_empty(){tx.execute("UPDATE atheros_search.embedding_jobs SET status='cancelled',owner_id=NULL,lease_token=NULL,lease_expires_at=NULL,last_error='search document superseded; embedding job cancelled',next_attempt_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE status IN('pending','leased') AND document_id::text=ANY($1::text[])",&[&superseded]).await?;}
    let tags:Vec<_>=document.tags.iter().map(|(kind,value)|json!({"type":kind,"value":value})).collect();
    let value=json!({"document_id":document.document_id,"source_key":s.key,"source_table":s.kind.source_table(),"source_kind":s.kind.source_kind(),"source_version":document.source_version,"source_mac":s.source_mac,"location_id":s.location_id,"sensor_id":s.sensor_id,"observed_at":s.observed_at,"bssid":s.bssid,"ssid":s.ssid,"frame_subtype":s.frame_subtype,"tags":tags,"detail_json":s.detail,"security_flags":s.security_flags,"handshake_captured":s.handshake,"title":document.title,"normalized_text":document.normalized_text,"normalized_sha256":document.normalized_sha256,
      "metadata":{"producer":"octopus","embedding_kind":s.kind.embedding_kind(),"normalized_sha256":document.normalized_sha256},"host":s.host,"proxy_device_id":s.proxy_device_id,"proxy_event_type":s.proxy_event_type,"blocked":s.blocked,"classification":s.classification,"window_start":s.window_start,"window_end":s.window_end,"evidence_revision":s.evidence_revision,"template_version":s.template_version,"normalization_version":s.normalization_version,"input_revision":s.input_revision});
    tx.execute(PERSIST_DOCUMENT,&[&value]).await?;
    tx.execute("DELETE FROM atheros_search.search_document_tokens WHERE document_id=$1::text::uuid",&[&document.document_id]).await?;
    for (token,frequency,count) in &document.tokens{tx.execute("INSERT INTO atheros_search.search_document_tokens(token,document_id,field_name,term_frequency,token_count,updated_at) VALUES($1,$2::text::uuid,'body',$3::double precision,$4,CURRENT_TIMESTAMP)",&[&token,&document.document_id,&frequency,&count]).await?;}
    tx.execute("DELETE FROM atheros_search.search_document_tags WHERE document_id=$1::text::uuid",&[&document.document_id]).await?;
    for (kind,value) in &document.tags{tx.execute("INSERT INTO atheros_search.search_document_tags(document_id,tag_type,tag_value,created_at) VALUES($1::text::uuid,$2,$3,CURRENT_TIMESTAMP)",&[&document.document_id,&kind,&value]).await?;}
    Ok(())
}

const PERSIST_DOCUMENT:&str=r#"INSERT INTO atheros_search.search_documents (
 document_id,source_id,source_key,source_table,source_kind,source_version,source_mac,location_id,sensor_id,observed_at,bssid,ssid,frame_subtype,tags,detail_json,security_flags,handshake_captured,title,normalized_text,normalized_sha256,search_vector,locale,status,metadata,host,proxy_device_id,proxy_event_type,blocked,classification,window_start,window_end,evidence_revision,template_version,normalization_version,input_revision,created_at,updated_at)
 SELECT v.document_id,v.source_key,v.source_key,v.source_table,v.source_kind,v.source_version,v.source_mac,v.location_id,v.sensor_id,v.observed_at,v.bssid,v.ssid,v.frame_subtype,v.tags,v.detail_json,v.security_flags,v.handshake_captured,v.title,v.normalized_text,v.normalized_sha256,to_tsvector('simple',v.normalized_text),'und','active',v.metadata,v.host,v.proxy_device_id,v.proxy_event_type,v.blocked,v.classification,v.window_start,v.window_end,v.evidence_revision,v.template_version,v.normalization_version,v.input_revision,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
 FROM jsonb_to_record($1::jsonb) AS v(document_id uuid,source_key text,source_table text,source_kind text,source_version bigint,source_mac text,location_id text,sensor_id text,observed_at timestamptz,bssid text,ssid text,frame_subtype text,tags jsonb,detail_json jsonb,security_flags int,handshake_captured bool,title text,normalized_text text,normalized_sha256 text,metadata jsonb,host text,proxy_device_id text,proxy_event_type text,blocked bool,classification text,window_start timestamptz,window_end timestamptz,evidence_revision bigint,template_version text,normalization_version text,input_revision text)
 ON CONFLICT(document_id) DO UPDATE SET status='active',source_key=EXCLUDED.source_key,source_table=EXCLUDED.source_table,source_kind=EXCLUDED.source_kind,source_mac=EXCLUDED.source_mac,location_id=EXCLUDED.location_id,sensor_id=EXCLUDED.sensor_id,observed_at=EXCLUDED.observed_at,bssid=EXCLUDED.bssid,ssid=EXCLUDED.ssid,frame_subtype=EXCLUDED.frame_subtype,security_flags=EXCLUDED.security_flags,handshake_captured=EXCLUDED.handshake_captured,tags=EXCLUDED.tags,detail_json=EXCLUDED.detail_json,title=EXCLUDED.title,normalized_text=EXCLUDED.normalized_text,normalized_sha256=EXCLUDED.normalized_sha256,search_vector=EXCLUDED.search_vector,source_version=EXCLUDED.source_version,metadata=EXCLUDED.metadata,host=EXCLUDED.host,proxy_device_id=EXCLUDED.proxy_device_id,proxy_event_type=EXCLUDED.proxy_event_type,blocked=EXCLUDED.blocked,classification=EXCLUDED.classification,window_start=EXCLUDED.window_start,window_end=EXCLUDED.window_end,evidence_revision=EXCLUDED.evidence_revision,template_version=EXCLUDED.template_version,normalization_version=EXCLUDED.normalization_version,input_revision=EXCLUDED.input_revision,updated_at=CURRENT_TIMESTAMP"#;

fn source_row(row:tokio_postgres::Row,kind:SearchKind)->SearchSource{
    let mut s=SearchSource::new(kind,row.get(0),row.get(4),row.get(10),row.get(11));s.source_mac=row.get(1);s.location_id=row.get(2);s.sensor_id=row.get(3);s.bssid=row.get(5);s.ssid=row.get(6);s.frame_subtype=row.get(7);s.security_flags=row.get(8);s.handshake=row.get(9);s
}
async fn candidates(tx:&mut PgTransaction,kind:SearchKind,limit:i32)->Result<Vec<SearchSource>,ProjectionError>{
    let query=match kind{SearchKind::Event=>Some(sql::EVENT_CANDIDATES),SearchKind::Device=>Some(sql::DEVICE_CANDIDATES),SearchKind::Behaviour=>Some(sql::BEHAVIOUR_CANDIDATES),SearchKind::Sequence=>Some(sql::SEQUENCE_CANDIDATES),_=>None};
    if let Some(query)=query{return Ok(tx.query(query,&[&limit.max(1)]).await?.into_iter().map(|r|source_row(r,kind)).collect());}
    let base=match kind{
        SearchKind::ObservationWindow=>"SELECT summary_id::text AS key,source_mac,location_id,sensor_id,last_seen AS observed_at,bssid,ssid,updated_at,jsonb_build_object('format_version',1,'kind','observation_window','window_start',window_start,'window_end',window_end,'frame_count',frame_count,'counters',counters,'radio',radio) AS detail FROM atheros_search.wireless_observation_summaries WHERE expires_at>CURRENT_TIMESTAMP",
        SearchKind::IdentitySummary=>"SELECT cluster_id AS key,NULL::text AS source_mac,NULL::text AS location_id,NULL::text AS sensor_id,COALESCE(last_seen,updated_at) AS observed_at,NULL::text AS bssid,NULL::text AS ssid,updated_at,jsonb_build_object('format_version',1,'kind','reviewed_identity_cluster','name',cluster_name,'member_count',cluster_size) AS detail FROM atheros_search.identity_clusters WHERE status='active'",
        SearchKind::DeviceProfile=>"SELECT node_id AS key,normalized_mac AS source_mac,location_id,sensor_id,observed_at,CASE WHEN node_kind='access_point' THEN normalized_mac END AS bssid,normalized_ssid AS ssid,updated_at,jsonb_build_object('format_version',1,'kind',node_kind,'attributes',node_payload) AS detail FROM atheros_search.wireless_topology_nodes WHERE node_kind='device'",
        SearchKind::ApProfile=>"SELECT node_id AS key,normalized_mac AS source_mac,location_id,sensor_id,observed_at,CASE WHEN node_kind='access_point' THEN normalized_mac END AS bssid,normalized_ssid AS ssid,updated_at,jsonb_build_object('format_version',1,'kind',node_kind,'attributes',node_payload) AS detail FROM atheros_search.wireless_topology_nodes WHERE node_kind='access_point'",
        _=>return Err(ProjectionError::Invalid("proxy candidates require bounded proxy-search-preparer")),
    };
    let statement=format!("WITH source AS ({base}) SELECT source.key,source.source_mac,source.location_id,source.sensor_id,source.observed_at,source.bssid,source.ssid,source.detail FROM source LEFT JOIN atheros_search.search_documents doc ON doc.source_kind=$1 AND doc.source_key=source.key AND doc.status='active' WHERE doc.document_id IS NULL OR doc.updated_at<source.updated_at ORDER BY source.updated_at,source.key LIMIT $2::int");
    Ok(tx.query(&statement,&[&kind.source_kind(),&limit.max(1)]).await?.into_iter().map(|r|{let detail:Value=r.get(7);let mut s=SearchSource::new(kind,r.get(0),r.get(4),detail.to_string(),detail);s.source_mac=r.get(1);s.location_id=r.get(2);s.sensor_id=r.get(3);s.bssid=r.get(5);s.ssid=r.get(6);s}).collect())
}
pub async fn enqueue_embedding(tx:&mut PgTransaction,document_id:&str,kind:SearchKind,model:&str,checksum:&str)->Result<(),ProjectionError>{
    let job_id=crate::util::stable_uuid("embedding",&[document_id,kind.embedding_kind(),model,checksum]);
    tx.execute("INSERT INTO atheros_search.embedding_jobs(job_id,document_id,embedding_kind,embedding_model,content_sha256,status,priority,attempt_count,max_attempts,next_attempt_at,created_at,updated_at) VALUES($1::text::uuid,$2::text::uuid,$3,$4,$5,'pending',100,0,5,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) ON CONFLICT(document_id,embedding_kind,embedding_model,content_sha256,input_revision) DO UPDATE SET job_id=embedding_jobs.job_id",&[&job_id,&document_id,&kind.embedding_kind(),&model,&checksum]).await?;Ok(())
}
impl ProjectionStore{
    fn supported_search_kinds(&self)->impl Iterator<Item=SearchKind>+'_ {SearchKind::NON_PROXY.into_iter().filter(|kind|if self.wireless.projection_only(){kind.compact()||kind.source_table()=="proxy_events"}else{!kind.compact()||self.wireless.enabled()})}
    pub async fn build_search_documents(&self,limit:i32)->Result<i32,ProjectionError>{
        let mut tx=self.runtime.begin_worker().await?;let mut count=0;
        for kind in self.supported_search_kinds(){for source in candidates(&mut tx,kind,limit).await?{persist_document(&mut tx,&prepare_source(source)?,false).await?;count+=1;}}
        tx.commit().await?;Ok(count)
    }
    pub async fn pending_embedding_job_count(&self)->Result<i64,ProjectionError>{let mut tx=self.runtime.begin_worker().await?;let count=tx.query("SELECT count(*) FROM atheros_search.embedding_jobs WHERE status='pending'",&[]).await?[0].get(0);tx.commit().await?;Ok(count)}
    pub async fn prepare_embedding_jobs(&self,limit:i32,model:&str)->Result<i32,ProjectionError>{
        let mut tx=self.runtime.begin_worker().await?;let mut count=0;
        for kind in self.supported_search_kinds(){
            let rows=tx.query("SELECT document.document_id::text,document.normalized_sha256 FROM atheros_search.search_documents document LEFT JOIN atheros_search.embedding_jobs job ON job.document_id=document.document_id AND job.embedding_kind=$1 AND job.embedding_model=$2 AND job.content_sha256=document.normalized_sha256 AND job.input_revision=document.input_revision WHERE document.status='active' AND document.source_kind=$3 AND job.job_id IS NULL ORDER BY document.observed_at,document.document_id LIMIT $4::int",&[&kind.embedding_kind(),&model,&kind.source_kind(),&limit.max(1)]).await?;
            for row in rows{enqueue_embedding(&mut tx,&row.get::<_,String>(0),kind,model,&row.get::<_,String>(1)).await?;count+=1;}
        }
        tx.commit().await?;Ok(count)
    }
}
