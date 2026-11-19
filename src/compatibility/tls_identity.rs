//! Native PKCS12 and JKS client identity decoding. SHA-1 is used solely for the
//! legacy JKS integrity/key-protection format; TLS uses OpenSSL's TLS policy.

use openssl::{
    hash::{hash, MessageDigest},
    memcmp,
    pkey::{PKey, Private},
    sha::Sha1,
    x509::X509,
};

pub struct ClientIdentity {
    pub certificate: X509,
    pub private_key: PKey<Private>,
    pub chain: Vec<X509>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid client TLS identity or password")]
pub struct IdentityError;

const MAX_STORE_BYTES: usize = 16 * 1024 * 1024;

pub fn decode(bytes: &[u8], password: &str, kind: &str) -> Result<ClientIdentity, IdentityError> {
    if bytes.len() > MAX_STORE_BYTES {
        return Err(IdentityError);
    }
    let identity = if kind.eq_ignore_ascii_case("PKCS12") {
        if password.contains('\0') {
            return Err(IdentityError);
        }
        let material = openssl::pkcs12::Pkcs12::from_der(bytes)
            .and_then(|value| value.parse2(password))
            .map_err(|_| IdentityError)?;
        ClientIdentity {
            certificate: material.cert.ok_or(IdentityError)?,
            private_key: material.pkey.ok_or(IdentityError)?,
            chain: material
                .ca
                .map(|chain| chain.into_iter().collect())
                .unwrap_or_default(),
        }
    } else if kind.eq_ignore_ascii_case("JKS") {
        jks(bytes, password)?
    } else {
        return Err(IdentityError);
    };
    if !identity
        .certificate
        .public_key()
        .map_err(|_| IdentityError)?
        .public_eq(&identity.private_key)
    {
        return Err(IdentityError);
    }
    Ok(identity)
}

pub fn load(path: &str, password: &str, kind: &str) -> Result<ClientIdentity, IdentityError> {
    let file = std::fs::File::open(path).map_err(|_| IdentityError)?;
    let metadata = file.metadata().map_err(|_| IdentityError)?;
    if !metadata.is_file() || metadata.len() > MAX_STORE_BYTES as u64 {
        return Err(IdentityError);
    }
    use std::io::Read;
    let mut bytes = Vec::new();
    file.take((MAX_STORE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| IdentityError)?;
    let result = decode(&bytes, password, kind);
    bytes.fill(0);
    result
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn bytes(&mut self, count: usize) -> Result<&'a [u8], IdentityError> {
        if count > self.0.len() {
            return Err(IdentityError);
        }
        let (value, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(value)
    }
    fn u32(&mut self) -> Result<u32, IdentityError> {
        Ok(u32::from_be_bytes(
            self.bytes(4)?.try_into().map_err(|_| IdentityError)?,
        ))
    }
    fn utf(&mut self) -> Result<&'a [u8], IdentityError> {
        let length = u16::from_be_bytes(self.bytes(2)?.try_into().map_err(|_| IdentityError)?);
        self.bytes(length as usize)
    }
    fn blob(&mut self) -> Result<&'a [u8], IdentityError> {
        let length = self.u32()?;
        self.bytes(length as usize)
    }
    fn der(&mut self, expected: u8) -> Result<Reader<'a>, IdentityError> {
        if self.bytes(1)?[0] != expected {
            return Err(IdentityError);
        }
        let first = self.bytes(1)?[0];
        let length = if first & 0x80 == 0 {
            first as usize
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0 || count > 4 {
                return Err(IdentityError);
            }
            let mut length = 0usize;
            for byte in self.bytes(count)? {
                length = (length << 8) | *byte as usize;
            }
            length
        };
        Ok(Reader(self.bytes(length)?))
    }
}

fn digest(parts: &[&[u8]]) -> [u8; 20] {
    let mut digest = Sha1::new();
    for part in parts {
        digest.update(part);
    }
    digest.finish()
}

fn unprotect(encoded: &[u8], password: &[u8]) -> Result<PKey<Private>, IdentityError> {
    let mut outer = Reader(encoded);
    let mut sequence = outer.der(0x30)?;
    let mut algorithm = sequence.der(0x30)?;
    let oid = algorithm.der(0x06)?;
    if oid.0 != [0x2b, 0x06, 0x01, 0x04, 0x01, 0x2a, 0x02, 0x11, 0x01, 0x01]
        || !(algorithm.0.is_empty() || algorithm.0 == [0x05, 0x00])
    {
        return Err(IdentityError);
    }
    let encrypted = sequence.der(0x04)?;
    if !outer.0.is_empty() || !sequence.0.is_empty() || encrypted.0.len() < 40 {
        return Err(IdentityError);
    }
    let (salt, body) = encrypted.0.split_at(20);
    let (body, expected) = body.split_at(body.len() - 20);
    let mut previous = salt.to_vec();
    let mut plaintext = Vec::with_capacity(body.len());
    for chunk in body.chunks(20) {
        let stream = digest(&[password, &previous]);
        plaintext.extend(chunk.iter().zip(stream).map(|(cipher, key)| cipher ^ key));
        previous.copy_from_slice(&stream);
    }
    let result = if memcmp::eq(&digest(&[password, &plaintext]), expected) {
        PKey::private_key_from_pkcs8(&plaintext).map_err(|_| IdentityError)
    } else {
        Err(IdentityError)
    };
    plaintext.fill(0);
    previous.fill(0);
    result
}

fn jks(bytes: &[u8], password: &str) -> Result<ClientIdentity, IdentityError> {
    if bytes.len() < 32 {
        return Err(IdentityError);
    }
    let (content, expected) = bytes.split_at(bytes.len() - 20);
    let mut password: Vec<u8> = password.encode_utf16().flat_map(u16::to_be_bytes).collect();
    let valid = memcmp::eq(
        &digest(&[&password, b"Mighty Aphrodite", content]),
        expected,
    );
    let result = if valid {
        jks_entries(content, &password)
    } else {
        Err(IdentityError)
    };
    password.fill(0);
    result
}

fn jks_entries(content: &[u8], password: &[u8]) -> Result<ClientIdentity, IdentityError> {
    let mut reader = Reader(content);
    if reader.u32()? != 0xfeedfeed {
        return Err(IdentityError);
    }
    let version = reader.u32()?;
    if ![1, 2].contains(&version) {
        return Err(IdentityError);
    }
    let count = reader.u32()?;
    if count > 1000 {
        return Err(IdentityError);
    }
    let mut identity = None;
    for _ in 0..count {
        let tag = reader.u32()?;
        reader.utf()?; // Alias uses modified UTF-8; it does not affect key selection.
        reader.bytes(8)?; // Entry creation timestamp.
        match tag {
            1 => {
                // Without a configured alias, multiple identities are ambiguous.
                if identity.is_some() {
                    return Err(IdentityError);
                }
                let private_key = unprotect(reader.blob()?, password)?;
                let count = reader.u32()?;
                if count == 0 || count > 1000 {
                    return Err(IdentityError);
                }
                let mut chain = Vec::new();
                for _ in 0..count {
                    chain.push(certificate(&mut reader, version)?);
                }
                let certificate = chain.remove(0);
                identity = Some(ClientIdentity {
                    certificate,
                    private_key,
                    chain,
                });
            }
            2 => {
                certificate(&mut reader, version)?;
            }
            _ => return Err(IdentityError),
        }
    }
    if !reader.0.is_empty() {
        return Err(IdentityError);
    }
    identity.ok_or(IdentityError)
}

fn certificate(reader: &mut Reader<'_>, version: u32) -> Result<X509, IdentityError> {
    if version == 2 && reader.utf()? != b"X.509" {
        return Err(IdentityError);
    }
    X509::from_der(reader.blob()?).map_err(|_| IdentityError)
}

/// Stable certificate identity for comparison with the independent Java oracle.
pub fn certificate_sha256(identity: &ClientIdentity) -> Result<String, IdentityError> {
    let digest = hash(
        MessageDigest::sha256(),
        &identity.certificate.to_der().map_err(|_| IdentityError)?,
    )
    .map_err(|_| IdentityError)?;
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}
