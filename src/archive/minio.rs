use super::{lowercase_sha256, ArchiveError};
use crate::util::sha256_hex;
use chrono::Utc;
use futures_util::StreamExt;
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use reqwest::{header::HeaderMap, Client, Method, Response, StatusCode, Url};
use std::{collections::BTreeMap, time::Duration};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredObject {
    pub size: i64,
    pub sha256: Option<String>,
    pub version_id: Option<String>,
    pub etag: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectVersion {
    pub key: String,
    pub version_id: String,
    pub last_modified: chrono::DateTime<Utc>,
    pub delete_marker: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectVersions {
    pub entries: Vec<ObjectVersion>,
    pub next_key_marker: Option<String>,
    pub next_version_marker: Option<String>,
}

/// Explicit static credentials, bounded requests, no redirect or implicit retries.
/// Debug intentionally omits credentials and endpoint query strings.
#[derive(Clone)]
pub struct MinioStore {
    client: Client,
    endpoint: Url,
    access_key: String,
    secret_key: String,
    region: String,
    bucket: String,
}

fn hmac(key: &[u8], bytes: &[u8]) -> Result<Vec<u8>, ArchiveError> {
    let key = PKey::hmac(key).map_err(|_| ArchiveError::Configuration)?;
    let mut signer =
        Signer::new(MessageDigest::sha256(), &key).map_err(|_| ArchiveError::Configuration)?;
    signer
        .update(bytes)
        .map_err(|_| ArchiveError::Configuration)?;
    signer
        .sign_to_vec()
        .map_err(|_| ArchiveError::Configuration)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn encode(value: &str, slash: bool) -> String {
    let mut result = String::new();
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) || (slash && b == b'/') {
            result.push(b as char);
        } else {
            result.push_str(&format!("%{b:02X}"));
        }
    }
    result
}

fn storage_error(error: reqwest::Error) -> ArchiveError {
    ArchiveError::Storage {
        retryable: error.is_timeout()
            || error.is_connect()
            || error.is_body()
            || error.is_request(),
        status: error.status().map(|s| s.as_u16()),
    }
}

fn status_error(status: StatusCode) -> ArchiveError {
    let status = status.as_u16();
    ArchiveError::Storage {
        retryable: status == 408 || status == 429 || status >= 500,
        status: Some(status),
    }
}

impl MinioStore {
    pub fn new(
        endpoint: &str,
        access_key: &str,
        secret_key: &str,
        region: &str,
        bucket: &str,
    ) -> Result<Self, ArchiveError> {
        Self::with_timeout(
            endpoint,
            access_key,
            secret_key,
            region,
            bucket,
            Duration::from_secs(10),
        )
    }

    pub fn with_timeout(
        endpoint: &str,
        access_key: &str,
        secret_key: &str,
        region: &str,
        bucket: &str,
        timeout: Duration,
    ) -> Result<Self, ArchiveError> {
        let endpoint = Url::parse(endpoint).map_err(|_| ArchiveError::Configuration)?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host_str().is_none()
            || endpoint.path() != "/"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || access_key.is_empty()
            || secret_key.is_empty()
            || region.is_empty()
            || bucket.is_empty()
            || bucket.contains('/')
            || bucket == "."
            || bucket == ".."
            || timeout.is_zero()
        {
            return Err(ArchiveError::Configuration);
        }
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(timeout)
            .timeout(timeout)
            .build()
            .map_err(|_| ArchiveError::Configuration)?;
        Ok(Self {
            client,
            endpoint,
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            region: region.into(),
            bucket: bucket.into(),
        })
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    fn location(&self, key: &str, query: &BTreeMap<String, String>) -> Result<Url, ArchiveError> {
        if key.split('/').any(|p| p == "." || p == "..") || key.starts_with('/') {
            return Err(ArchiveError::Configuration);
        }
        let path = if key.is_empty() {
            format!("/{}", encode(&self.bucket, false))
        } else {
            format!("/{}/{}", encode(&self.bucket, false), encode(key, true))
        };
        let mut url = self.endpoint.clone();
        url.set_path(&path);
        if !query.is_empty() {
            url.set_query(Some(
                &query
                    .iter()
                    .map(|(k, v)| format!("{}={}", encode(k, false), encode(v, false)))
                    .collect::<Vec<_>>()
                    .join("&"),
            ));
        }
        Ok(url)
    }

    fn signing_key(&self, date: &str) -> Result<Vec<u8>, ArchiveError> {
        let date = hmac(
            format!("AWS4{}", self.secret_key).as_bytes(),
            date.as_bytes(),
        )?;
        let region = hmac(&date, self.region.as_bytes())?;
        let service = hmac(&region, b"s3")?;
        hmac(&service, b"aws4_request")
    }

    async fn request(
        &self,
        method: Method,
        key: &str,
        query: BTreeMap<String, String>,
        bytes: Option<&[u8]>,
        sha_metadata: Option<&str>,
    ) -> Result<Response, ArchiveError> {
        self.request_with_condition(method, key, query, bytes, sha_metadata, false)
            .await
    }

    async fn request_with_condition(
        &self,
        method: Method,
        key: &str,
        query: BTreeMap<String, String>,
        bytes: Option<&[u8]>,
        sha_metadata: Option<&str>,
        create_only: bool,
    ) -> Result<Response, ArchiveError> {
        let now = Utc::now();
        let date = now.format("%Y%m%d").to_string();
        let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();
        let url = self.location(key, &query)?;
        let host = match url.port() {
            Some(port) => format!(
                "{}:{port}",
                url.host_str().ok_or(ArchiveError::Configuration)?
            ),
            None => url.host_str().ok_or(ArchiveError::Configuration)?.into(),
        };
        let payload_hash = sha256_hex(bytes.unwrap_or_default());
        let mut signed = BTreeMap::from([
            ("host", host),
            ("x-amz-content-sha256", payload_hash.clone()),
            ("x-amz-date", timestamp.clone()),
        ]);
        if let Some(sha) = sha_metadata {
            signed.insert("x-amz-meta-sha256", sha.into());
        }
        if create_only {
            signed.insert("if-none-match", "*".into());
        }
        let canonical_headers = signed
            .iter()
            .map(|(k, v)| format!("{k}:{}\n", v.trim()))
            .collect::<String>();
        let signed_headers = signed.keys().copied().collect::<Vec<_>>().join(";");
        let canonical = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method,
            url.path(),
            url.query().unwrap_or(""),
            canonical_headers,
            signed_headers,
            payload_hash
        );
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
            sha256_hex(canonical)
        );
        let signature = hex(&hmac(&self.signing_key(&date)?, to_sign.as_bytes())?);
        let mut request = self.client.request(method, url);
        for (k, v) in signed {
            request = request.header(k, v);
        }
        request=request.header("Authorization",format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",self.access_key));
        if let Some(bytes) = bytes {
            request = request
                .header("content-type", "application/json")
                .body(bytes.to_vec());
        }
        request.send().await.map_err(storage_error)
    }

    pub async fn initialize(&self) -> Result<(), ArchiveError> {
        let response = self
            .request(Method::HEAD, "", BTreeMap::new(), None, None)
            .await?;
        if response.status().is_success() {
            return Ok(());
        }
        if response.status() != StatusCode::NOT_FOUND {
            return Err(status_error(response.status()));
        }
        let response = self
            .request(Method::PUT, "", BTreeMap::new(), None, None)
            .await?;
        if response.status().is_success() {
            return Ok(());
        }
        let status = response.status();
        if status == StatusCode::CONFLICT {
            let body = read_bounded(response, 16384).await?;
            if String::from_utf8_lossy(&body).contains("<Code>BucketAlreadyOwnedByYou</Code>") {
                return Ok(());
            }
        }
        Err(status_error(status))
    }

    pub async fn initialize_existing_versioned_encrypted(&self) -> Result<(), ArchiveError> {
        let response = self
            .request(Method::HEAD, "", BTreeMap::new(), None, None)
            .await?;
        if !response.status().is_success() {
            return Err(status_error(response.status()));
        }
        for (query, required) in [
            ("versioning", "<Status>Enabled</Status>"),
            ("encryption", "<Rule>"),
        ] {
            let response = self
                .request(
                    Method::GET,
                    "",
                    BTreeMap::from([(query.into(), String::new())]),
                    None,
                    None,
                )
                .await?;
            if !response.status().is_success() {
                return Err(status_error(response.status()));
            }
            let body = read_bounded(response, 65536).await?;
            if !String::from_utf8_lossy(&body).contains(required) {
                return Err(ArchiveError::Response(if query == "versioning" {
                    "artifact bucket versioning required"
                } else {
                    "artifact bucket encryption required"
                }));
            }
        }
        Ok(())
    }

    pub async fn stat_versioned(
        &self,
        key: &str,
        version: Option<&str>,
    ) -> Result<Option<StoredObject>, ArchiveError> {
        let query = version_query(version)?;
        let response = self.request(Method::HEAD, key, query, None, None).await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(status_error(response.status()));
        }
        Ok(Some(metadata(response.headers(), true)?))
    }

    pub async fn put_versioned(
        &self,
        key: &str,
        bytes: &[u8],
        sha: &str,
    ) -> Result<StoredObject, ArchiveError> {
        if !lowercase_sha256(sha) || sha256_hex(bytes) != sha {
            return Err(ArchiveError::Integrity);
        }
        let response = self
            .request(Method::PUT, key, BTreeMap::new(), Some(bytes), Some(sha))
            .await?;
        if !response.status().is_success() {
            return Err(status_error(response.status()));
        }
        let mut value = metadata(response.headers(), false)?;
        value.size = bytes.len() as i64;
        value.sha256 = Some(sha.into());
        Ok(value)
    }

    pub async fn put_verified(
        &self,
        key: &str,
        bytes: &[u8],
        sha: &str,
    ) -> Result<(), ArchiveError> {
        if !lowercase_sha256(sha) || sha256_hex(bytes) != sha {
            return Err(ArchiveError::Integrity);
        }
        let version = if let Some(existing) = self.stat_versioned(key, None).await? {
            existing.version_id.clone()
        } else {
            let response = self
                .request_with_condition(
                    Method::PUT,
                    key,
                    BTreeMap::new(),
                    Some(bytes),
                    Some(sha),
                    true,
                )
                .await?;
            if response.status() == StatusCode::PRECONDITION_FAILED {
                self.stat_versioned(key, None)
                    .await?
                    .ok_or(ArchiveError::Integrity)?
                    .version_id
            } else if response.status().is_success() {
                metadata(response.headers(), false)?.version_id
            } else {
                return Err(status_error(response.status()));
            }
        };
        let existing = self
            .stat_versioned(key, version.as_deref())
            .await?
            .ok_or(ArchiveError::Integrity)?;
        if existing.size != bytes.len() as i64
            || existing.sha256.as_deref().is_some_and(|value| value != sha)
        {
            return Err(ArchiveError::Integrity);
        }
        let stored = self
            .get_versioned(key, existing.version_id.as_deref(), bytes.len())
            .await?;
        if stored != bytes {
            return Err(ArchiveError::Integrity);
        }
        Ok(())
    }

    pub async fn get_versioned(
        &self,
        key: &str,
        version: Option<&str>,
        max_bytes: usize,
    ) -> Result<Vec<u8>, ArchiveError> {
        let response = self
            .request(Method::GET, key, version_query(version)?, None, None)
            .await?;
        if !response.status().is_success() {
            return Err(status_error(response.status()));
        }
        read_bounded(response, max_bytes).await
    }

    pub async fn get_verified(
        &self,
        key: &str,
        sha: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, ArchiveError> {
        let bytes = self.get_versioned(key, None, max_bytes).await?;
        if !lowercase_sha256(sha) || sha256_hex(&bytes) != sha {
            return Err(ArchiveError::Integrity);
        }
        Ok(bytes)
    }

    pub async fn delete(&self, key: &str, version: Option<&str>) -> Result<(), ArchiveError> {
        let response = self
            .request(Method::DELETE, key, version_query(version)?, None, None)
            .await?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        if let Some(version) = version.filter(|_| status == StatusCode::NOT_FOUND) {
            let bytes = read_bounded(response, 8 * 1024).await?;
            if let Ok(body) = std::str::from_utf8(&bytes) {
                if is_missing_version(body, key, version) {
                    return Ok(());
                }
            }
        }
        Err(status_error(status))
    }

    /// Bounded S3 version listing. Both cursors must be carried into the next
    /// page; callers must still check durable references before exact deletion.
    pub async fn list_versions(
        &self,
        prefix: &str,
        key_marker: Option<&str>,
        version_marker: Option<&str>,
    ) -> Result<ObjectVersions, ArchiveError> {
        if version_marker.is_some() && key_marker.is_none() {
            return Err(ArchiveError::Configuration);
        }
        let mut query = BTreeMap::from([
            ("versions".into(), String::new()),
            ("prefix".into(), prefix.into()),
            ("max-keys".into(), "1000".into()),
        ]);
        if let Some(key) = key_marker {
            query.insert("key-marker".into(), key.into());
        }
        if let Some(version) = version_marker {
            query.insert("version-id-marker".into(), version.into());
        }
        let response = self.request(Method::GET, "", query, None, None).await?;
        if !response.status().is_success() {
            return Err(status_error(response.status()));
        }
        let body = read_bounded(response, 2 * 1024 * 1024).await?;
        let body = std::str::from_utf8(&body)
            .map_err(|_| ArchiveError::Response("version listing is not UTF-8"))?;
        parse_versions(body)
    }

    pub fn presign_get(
        &self,
        key: &str,
        version: &str,
        expires_secs: u32,
    ) -> Result<String, ArchiveError> {
        if !(1..=604800).contains(&expires_secs) {
            return Err(ArchiveError::Configuration);
        }
        let now = Utc::now();
        let date = now.format("%Y%m%d").to_string();
        let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let mut query = version_query(Some(version))?;
        query.extend([
            ("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()),
            (
                "X-Amz-Credential".into(),
                format!("{}/{scope}", self.access_key),
            ),
            ("X-Amz-Date".into(), timestamp.clone()),
            ("X-Amz-Expires".into(), expires_secs.to_string()),
            ("X-Amz-SignedHeaders".into(), "host".into()),
        ]);
        let mut url = self.location(key, &query)?;
        let host = match url.port() {
            Some(port) => format!(
                "{}:{port}",
                url.host_str().ok_or(ArchiveError::Configuration)?
            ),
            None => url.host_str().ok_or(ArchiveError::Configuration)?.into(),
        };
        let canonical = format!(
            "GET\n{}\n{}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD",
            url.path(),
            url.query().unwrap_or("")
        );
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
            sha256_hex(canonical)
        );
        let signature = hex(&hmac(&self.signing_key(&date)?, to_sign.as_bytes())?);
        url.set_query(Some(&format!(
            "{}&X-Amz-Signature={signature}",
            url.query().unwrap_or("")
        )));
        Ok(url.into())
    }
}

fn version_query(version: Option<&str>) -> Result<BTreeMap<String, String>, ArchiveError> {
    match version {
        None => Ok(BTreeMap::new()),
        Some("" | "null") => Err(ArchiveError::Configuration),
        Some(value) => Ok(BTreeMap::from([("versionId".into(), value.into())])),
    }
}

fn metadata(headers: &HeaderMap, require_size: bool) -> Result<StoredObject, ArchiveError> {
    let text = |key: &str| {
        headers
            .get(key)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let size = text("content-length")
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v >= 0);
    if require_size && size.is_none() {
        return Err(ArchiveError::Response("object size missing"));
    }
    Ok(StoredObject {
        size: size.unwrap_or(0),
        sha256: text("x-amz-meta-sha256"),
        version_id: text("x-amz-version-id").filter(|v| !v.is_empty() && v != "null"),
        etag: text("etag")
            .ok_or(ArchiveError::Response("object etag missing"))?
            .trim_matches('"')
            .into(),
    })
}

async fn read_bounded(response: Response, max_bytes: usize) -> Result<Vec<u8>, ArchiveError> {
    if response
        .content_length()
        .is_some_and(|n| n > max_bytes as u64)
    {
        return Err(ArchiveError::Response("object exceeds maximum size"));
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(storage_error)?;
        if chunk.len() > max_bytes.saturating_sub(bytes.len()) {
            return Err(ArchiveError::Response("object exceeds maximum size"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn is_missing_version(body: &str, key: &str, version: &str) -> bool {
    parse_delete_error_xml(body).is_some_and(|[code, object, object_version]| {
        code.as_deref() == Some("NoSuchVersion")
            && object.as_deref().is_none_or(|value| value == key)
            && object_version
                .as_deref()
                .is_none_or(|value| value == version)
    })
}

// Parse the bounded UTF-8 S3 error as XML 1.0. The token grammar deliberately
// has no DTD or entity declarations. Text accepts only predefined and numeric
// references, so parsing cannot resolve external resources.
fn parse_delete_error_xml(body: &str) -> Option<[Option<String>; 3]> {
    use std::{collections::HashSet, sync::LazyLock};

    const NAME_START: &str = r":A-Z_a-z\u{C0}-\u{D6}\u{D8}-\u{F6}\u{F8}-\u{2FF}\u{370}-\u{37D}\u{37F}-\u{1FFF}\u{200C}-\u{200D}\u{2070}-\u{218F}\u{2C00}-\u{2FEF}\u{3001}-\u{D7FF}\u{F900}-\u{FDCF}\u{FDF0}-\u{FFFD}\u{10000}-\u{EFFFF}";
    static NAME: LazyLock<String> = LazyLock::new(|| {
        format!(
            r"[{NAME_START}][{NAME_START}.0-9\u{{B7}}\u{{300}}-\u{{36F}}\u{{203F}}-\u{{2040}}-]*"
        )
    });
    static ATTR: LazyLock<String> = LazyLock::new(|| {
        format!(
            r#"(?-x:[ \t\n]+)({})[\t\n\x20]*=[\t\n\x20]*(?:"([^"<]*)"|'([^'<]*)')"#,
            *NAME
        )
    });
    static ATTRIBUTES: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(&ATTR).expect("XML attribute grammar"));
    static TOKEN: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(&format!(
            r#"(?sx)\A(?:
                (?P<declaration><\?xml[\x20\t\n]+version[\x20\t\n]*=[\x20\t\n]*(?:"1\.0"|'1\.0')
                    (?:[\x20\t\n]+encoding[\x20\t\n]*=[\x20\t\n]*(?:"(?i:utf-8)"|'(?i:utf-8)'))?
                    (?:[\x20\t\n]+standalone[\x20\t\n]*=[\x20\t\n]*(?:"(?:yes|no)"|'(?:yes|no)'))?
                    [\x20\t\n]*\?>)
                | <!--(?P<comment>.*?)-->
                | <!\[CDATA\[(?P<cdata>.*?)\]\]>
                | </(?P<end>{name})[\x20\t\n]*>
                | <(?P<start>{name})(?P<attributes>(?:{attribute})*)[\x20\t\n]*(?P<empty>/?)>
                | <\?(?P<instruction>{name})(?:[\x20\t\n]+.*?)?\?>
                | (?P<text>[^<]+)
            )"#,
            name = *NAME,
            attribute = *ATTR,
        ))
        .expect("XML token grammar")
    });

    let normalized = body.replace("\r\n", "\n").replace('\r', "\n");
    let document = normalized.strip_prefix('\u{feff}').unwrap_or(&normalized);
    if !document.chars().all(xml_character) {
        return None;
    }
    let mut rest = document;
    let mut root_seen = false;
    let mut elements = Vec::new();
    let mut values = [None, None, None];
    let field = |name| {
        ["Code", "Key", "VersionId"]
            .iter()
            .position(|tag| *tag == name)
    };
    while !rest.is_empty() {
        let token = TOKEN.captures(rest)?;
        let get = |name| token.name(name).map(|part| part.as_str());
        let active = if elements.len() == 2 {
            field(elements[1])
        } else {
            None
        };
        if let Some(name) = get("start") {
            if elements.is_empty() {
                if root_seen || name != "Error" {
                    return None;
                }
                root_seen = true;
            }
            if active.is_some() {
                return None;
            }
            if let Some(index) = field(name).filter(|_| elements.len() == 1) {
                if values[index].replace(String::new()).is_some() {
                    return None;
                }
            }
            let mut names = HashSet::new();
            for attribute in ATTRIBUTES.captures_iter(get("attributes")?) {
                if !names.insert(attribute.get(1)?.as_str()) {
                    return None;
                }
                let value = attribute.get(2).or_else(|| attribute.get(3))?.as_str();
                decode_xml_text(value).ok()?;
            }
            if get("empty") == Some("") {
                elements.push(name);
            }
        } else if let Some(name) = get("end") {
            if elements.pop() != Some(name) {
                return None;
            }
        } else if let Some(text) = get("text") {
            if text.contains("]]>")
                || (elements.is_empty() && !text.trim_matches([' ', '\t', '\n']).is_empty())
            {
                return None;
            }
            let text = decode_xml_text(text).ok()?;
            if let Some(index) = active {
                values[index].as_mut()?.push_str(&text);
            }
        } else if let Some(cdata) = get("cdata") {
            if elements.is_empty() {
                return None;
            }
            if let Some(index) = active {
                values[index].as_mut()?.push_str(cdata);
            }
        } else if get("comment")
            .is_some_and(|comment| comment.contains("--") || comment.ends_with('-'))
            || get("instruction").is_some_and(|name| name.eq_ignore_ascii_case("xml"))
            || (get("declaration").is_some() && rest.len() != document.len())
        {
            return None;
        }
        rest = &rest[token.get(0)?.end()..];
    }
    (root_seen && elements.is_empty()).then_some(values)
}

fn xml_character(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}

fn xml_text(xml: &str, tag: &str) -> Result<Option<String>, ArchiveError> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let Some(start) = xml.find(&open) else {
        return Ok(None);
    };
    let rest = &xml[start + open.len()..];
    let end = rest
        .find(&close)
        .ok_or(ArchiveError::Response("invalid version XML"))?;
    decode_xml_text(&rest[..end]).map(Some)
}

fn decode_xml_text(mut text: &str) -> Result<String, ArchiveError> {
    let mut value = String::new();
    while let Some(index) = text.find('&') {
        value.push_str(&text[..index]);
        text = &text[index + 1..];
        let end = text
            .find(';')
            .ok_or(ArchiveError::Response("invalid XML escape"))?;
        let entity = &text[..end];
        let c = match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            v if v.starts_with("#x") && v[2..].bytes().all(|b| b.is_ascii_hexdigit()) => {
                u32::from_str_radix(&v[2..], 16)
                    .ok()
                    .and_then(char::from_u32)
                    .filter(|c| xml_character(*c))
                    .ok_or(ArchiveError::Response("invalid XML escape"))?
            }
            v if v.starts_with('#') && v[1..].bytes().all(|b| b.is_ascii_digit()) => v[1..]
                .parse::<u32>()
                .ok()
                .and_then(char::from_u32)
                .filter(|c| xml_character(*c))
                .ok_or(ArchiveError::Response("invalid XML escape"))?,
            _ => return Err(ArchiveError::Response("unsupported XML entity")),
        };
        value.push(c);
        text = &text[end + 1..];
    }
    value.push_str(text);
    Ok(value)
}

fn parse_versions(xml: &str) -> Result<ObjectVersions, ArchiveError> {
    if xml.contains("<!DOCTYPE") || xml.contains("<!ENTITY") || !xml.contains("<ListVersionsResult")
    {
        return Err(ArchiveError::Response("invalid version XML"));
    }
    let required = |body: &str, tag: &str| {
        xml_text(body, tag)?.ok_or(ArchiveError::Response("missing version field"))
    };
    let mut entries = Vec::new();
    for (tag, delete_marker) in [("Version", false), ("DeleteMarker", true)] {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let mut rest = xml;
        while let Some(start) = rest.find(&open) {
            let body = &rest[start + open.len()..];
            let end = body
                .find(&close)
                .ok_or(ArchiveError::Response("invalid version XML"))?;
            let value = &body[..end];
            let last_modified = required(value, "LastModified")?
                .parse()
                .map_err(|_| ArchiveError::Response("invalid version timestamp"))?;
            let version_id = required(value, "VersionId")?;
            if version_id.is_empty() {
                return Err(ArchiveError::Response("missing version ID"));
            }
            entries.push(ObjectVersion {
                key: required(value, "Key")?,
                version_id,
                last_modified,
                delete_marker,
            });
            if entries.len() > 1000 {
                return Err(ArchiveError::Response("version listing exceeds maximum"));
            }
            rest = &body[end + close.len()..];
        }
    }
    let truncated = required(xml, "IsTruncated")?;
    let (next_key_marker, next_version_marker) = match truncated.as_str() {
        "false" => (None, None),
        "true" => (
            Some(required(xml, "NextKeyMarker")?),
            Some(required(xml, "NextVersionIdMarker")?),
        ),
        _ => return Err(ArchiveError::Response("invalid pagination flag")),
    };
    Ok(ObjectVersions {
        entries,
        next_key_marker,
        next_version_marker,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_path_and_signing_reject_ambiguous_inputs() {
        let store = MinioStore::new(
            "http://localhost:9000",
            "key",
            "secret",
            "us-east-1",
            "bucket",
        )
        .unwrap();
        let url = store
            .location(
                "a b/%/file",
                &BTreeMap::from([("versionId".into(), "a+b/=".into())]),
            )
            .unwrap();
        assert_eq!(
            url.as_str(),
            "http://localhost:9000/bucket/a%20b/%25/file?versionId=a%2Bb%2F%3D"
        );
        assert!(store.location("a/../file", &BTreeMap::new()).is_err());
        assert!(store.presign_get("a", "null", 60).is_err());
        assert!(MinioStore::new(
            "http://name:pass@localhost:9000",
            "key",
            "secret",
            "region",
            "bucket"
        )
        .is_err());
        let presigned = store.presign_get("a b", "version/+", 60).unwrap();
        assert!(presigned.contains("versionId=version%2F%2B"));
        assert!(presigned.contains("X-Amz-Signature="));
    }
    #[test]
    fn version_xml_is_bounded_and_decodes_escaped_keys() {
        let xml = r#"<ListVersionsResult><Version><Key>i/n/a&amp;b</Key><VersionId>id</VersionId><LastModified>2026-01-01T00:00:00Z</LastModified></Version><DeleteMarker><Key>gone</Key><VersionId>deleted-id</VersionId><LastModified>2026-01-01T00:00:01Z</LastModified></DeleteMarker><IsTruncated>true</IsTruncated><NextKeyMarker>next&amp;key</NextKeyMarker><NextVersionIdMarker>next-version</NextVersionIdMarker></ListVersionsResult>"#;
        let page = parse_versions(xml).unwrap();
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.entries[0].key, "i/n/a&b");
        assert!(page.entries[1].delete_marker);
        assert_eq!(page.next_key_marker.as_deref(), Some("next&key"));
        assert!(parse_versions("<!DOCTYPE evil><ListVersionsResult/>").is_err());
        assert!(parse_versions(
            "<ListVersionsResult><IsTruncated>true</IsTruncated></ListVersionsResult>"
        )
        .is_err());
        assert!(xml_text("<Key>&evil;</Key>", "Key").is_err());
    }

    #[test]
    fn delete_404_requires_an_unambiguous_missing_version() {
        let key = "artifacts/a&b";
        let version = "v1";
        for (fields, accepted) in [
            ("", true),
            (
                "<Key>artifacts/a&amp;b</Key><VersionId>v1</VersionId>",
                true,
            ),
            ("<Key>artifacts/a&amp;b</Key>", true),
            ("<VersionId>v1</VersionId>", true),
            ("<Key>artifacts/a&amp;b</Key><Key>other</Key>", false),
            ("<VersionId>v1</VersionId><VersionId>v1</VersionId>", false),
            ("<VersionId>v1</VersionId><VersionId/>", false),
            ("<Key>other</Key>", false),
            ("<VersionId>v2</VersionId>", false),
            ("<Code>NoSuchBucket</Code>", false),
        ] {
            let body =
                format!("<?xml version=\"1.0\"?><Error><Code>NoSuchVersion</Code>{fields}</Error>");
            assert_eq!(is_missing_version(&body, key, version), accepted, "{body}");
        }
        for body in [
            "",
            "<Error><Code>NoSuchBucket</Code></Error>",
            "<Error><Details><Code>NoSuchVersion</Code></Details></Error>",
            "<Error><Code>NoSuchVersion</Code><Other></Wrong></Error>",
            "<Error/><Error><Code>NoSuchVersion</Code></Error>",
            "<Error><Code>NoSuchVersion</Code><Key>&undefined;</Key></Error>",
            "<Error><Code>NoSuchVersion</Code><Key>&#0;</Key></Error>",
            "<Error><Code>NoSuchVersion</Code><Other a='x' a='y'/></Error>",
            "<Error><Code>NoSuchVersion</Code><Other>bad]]></Other></Error>",
            "<Error><Code>NoSuchVersion</Code><!-- bad -- comment --></Error>",
            "<!DOCTYPE Error SYSTEM 'https://example.test/dtd'><Error><Code>NoSuchVersion</Code></Error>",
            "<!DOCTYPE Error [<!ENTITY value 'NoSuchVersion'>]><Error><Code>&value;</Code></Error>",
        ] {
            assert!(!is_missing_version(body, key, version), "{body}");
        }
        assert!(is_missing_version(
            "<?xml version='1.0' encoding='UTF-8'?><Error><!-- <Key>ignored</Key> --><VersionId>v1</VersionId><Code><![CDATA[NoSuchVersion]]></Code><Detail request='example'/></Error>",
            key,
            version,
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn real_minio_exact_version_integrity_and_presigned_access() {
        use std::process::Command;
        let checked = |cmd: &mut Command| {
            let out = cmd.output().expect("test command starts");
            assert!(
                out.status.success(),
                "MinIO fixture command failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            out
        };
        let available = Command::new("docker")
            .arg("info")
            .output()
            .is_ok_and(|v| v.status.success());
        if !available {
            assert_ne!(
                std::env::var("OCTOPUS_REQUIRE_DOCKER").as_deref(),
                Ok("true"),
                "required MinIO Docker unavailable"
            );
            eprintln!("Docker unavailable; native MinIO exact-version test not exercised");
            return;
        }
        let name = format!("native-minio-versions-{}", uuid::Uuid::new_v4());
        checked(Command::new("docker").args([
            "run",
            "-d",
            "--name",
            &name,
            "-p",
            "127.0.0.1::9000",
            "-e",
            "MINIO_ROOT_USER=archive-test",
            "-e",
            "MINIO_ROOT_PASSWORD=archive-test-password",
            "-e",
            "MINIO_KMS_SECRET_KEY=archive-test:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "elestio/minio@sha256:25348a257f1ece1b192f25f6cd9854618fa86422ac87b494b5d4e629c556d4bd",
            "server",
            "/data",
        ]));
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = Command::new("docker")
                    .args(["rm", "-f", "-v", &self.0])
                    .output();
            }
        }
        let _cleanup = Cleanup(name.clone());
        let output = checked(Command::new("docker").args(["port", &name, "9000/tcp"]));
        let endpoint = format!(
            "http://{}",
            String::from_utf8(output.stdout).unwrap().trim()
        );
        let store = MinioStore::new(
            &endpoint,
            "archive-test",
            "archive-test-password",
            "us-east-1",
            "versioned-artifacts",
        )
        .unwrap();
        let mut ready = false;
        for _ in 0..120 {
            if store.initialize().await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(ready, "MinIO did not become ready");
        assert!(store
            .initialize_existing_versioned_encrypted()
            .await
            .is_err());
        let versioning=b"<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>";
        let response = store
            .request(
                Method::PUT,
                "",
                BTreeMap::from([("versioning".into(), String::new())]),
                Some(versioning),
                None,
            )
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "versioning status {}",
            response.status()
        );
        assert!(store
            .initialize_existing_versioned_encrypted()
            .await
            .is_err());
        let encryption=b"<ServerSideEncryptionConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
        let response = store
            .request(
                Method::PUT,
                "",
                BTreeMap::from([("encryption".into(), String::new())]),
                Some(encryption),
                None,
            )
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "encryption status {}",
            response.status()
        );
        store
            .initialize_existing_versioned_encrypted()
            .await
            .unwrap();
        let original = br#"{"immutable":true}"#;
        let replaced = br#"{"newer":true}"#;
        let key = "installation/namespace/inputs/run/artifact";
        let first = store
            .put_versioned(key, original, &sha256_hex(original))
            .await
            .unwrap();
        let version = first
            .version_id
            .as_deref()
            .expect("non-null immutable version");
        let second = store
            .put_versioned(key, replaced, &sha256_hex(replaced))
            .await
            .unwrap();
        assert_ne!(first.version_id, second.version_id);
        assert_eq!(
            store.get_versioned(key, Some(version), 1024).await.unwrap(),
            original
        );
        assert_eq!(
            store.get_versioned(key, None, 1024).await.unwrap(),
            replaced
        );
        let stat = store
            .stat_versioned(key, Some(version))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stat.etag, first.etag);
        assert_eq!(stat.sha256, Some(sha256_hex(original)));
        assert!(store.get_versioned(key, Some(version), 1).await.is_err());
        let url = store.presign_get(key, version, 60).unwrap();
        let response = Client::new().get(url).send().await.unwrap();
        assert!(
            response.status().is_success(),
            "presign status {}",
            response.status()
        );
        assert_eq!(response.bytes().await.unwrap().as_ref(), original);
        let versions = store
            .list_versions("installation/namespace/", None, None)
            .await
            .unwrap();
        assert_eq!(versions.entries.len(), 2);
        assert!(versions.next_key_marker.is_none());
        assert!(versions
            .entries
            .iter()
            .all(|v| v.key == key && !v.delete_marker));
        store.delete(key, Some(version)).await.unwrap();
        assert!(store
            .stat_versioned(key, Some(version))
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            store.get_versioned(key, None, 1024).await.unwrap(),
            replaced
        );
        assert!(store
            .put_versioned("wrong", original, &"f".repeat(64))
            .await
            .is_err());
        let wrong = MinioStore::new(
            &endpoint,
            "archive-test",
            "wrong-password",
            "us-east-1",
            "versioned-artifacts",
        )
        .unwrap();
        assert!(matches!(
            wrong.initialize().await,
            Err(ArchiveError::Storage {
                retryable: false,
                status: Some(403)
            })
        ));
    }
}
