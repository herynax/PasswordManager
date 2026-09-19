use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::errors::{Error, Result};

pub const PAYLOAD_SPEC_VERSION: u16 = 1;
pub const MAX_TAGS: usize = 32;
pub const MAX_ENTRIES: usize = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryType {
    Login = 1,
    Note = 2,
}

impl EntryType {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(EntryType::Login),
            2 => Ok(EntryType::Note),
            _ => Err(Error::InvalidFormat("unknown entry type")),
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl Serialize for EntryType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(self.to_u8())
    }
}

impl<'de> Deserialize<'de> for EntryType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = u8::deserialize(deserializer)?;
        EntryType::from_u8(v).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoginData {
    pub username: String,
    pub password: String,
    pub url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoteData {
    pub body: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum EntryBody {
    Login(LoginData),
    Note(NoteData),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub title: String,
    pub tags: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub body: EntryBody,
}

impl EntryType {
    pub fn label(&self) -> &'static str {
        match self {
            EntryType::Login => "login",
            EntryType::Note => "note",
        }
    }
}

pub fn now_unix() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Payload {
    pub spec_version: u16,
    pub entries: Vec<Entry>,
}

impl Payload {
    pub fn new() -> Self {
        Payload {
            spec_version: PAYLOAD_SPEC_VERSION,
            entries: Vec::new(),
        }
    }
}

impl Default for Payload {
    fn default() -> Self {
        Self::new()
    }
}

pub fn encode(payload: &Payload) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(payload, &mut buf).map_err(|_| Error::Crypto)?;
    Ok(buf)
}

pub fn decode(bytes: &[u8]) -> Result<Payload> {
    let wrapped = ciborium::from_reader::<Payload, _>(bytes)
        .map_err(|_| Error::InvalidFormat("malformed payload"))?;
    if wrapped.spec_version != PAYLOAD_SPEC_VERSION {
        return Err(Error::InvalidFormat("unsupported payload spec version"));
    }
    if wrapped.entries.len() > MAX_ENTRIES {
        return Err(Error::InvalidFormat("too many entries"));
    }
    Ok(wrapped)
}

pub fn generate_id() -> Result<String> {
    let mut b: [u8; 16] = crate::crypto::random::random_array()?;
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    let hex = b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> Entry {
        Entry {
            id: "00000000-0000-4000-8000-000000000000".to_string(),
            title: "GitHub".to_string(),
            tags: vec!["dev".to_string()],
            created_at: now_unix(),
            updated_at: now_unix(),
            body: EntryBody::Login(LoginData {
                username: "octocat".to_string(),
                password: "s3cret".to_string(),
                url: "https://github.com".to_string(),
            }),
        }
    }

    #[test]
    fn entry_type_from_u8_rejects_unknown() {
        assert_eq!(EntryType::from_u8(1), Ok(EntryType::Login));
        assert_eq!(EntryType::from_u8(2), Ok(EntryType::Note));
        assert!(EntryType::from_u8(0).is_err());
        assert!(EntryType::from_u8(9).is_err());
    }

    #[test]
    fn payload_roundtrip() {
        let mut p = Payload::new();
        p.entries.push(sample_entry());
        let bytes = encode(&p).unwrap();
        let back = decode(&bytes).unwrap();
        assert_eq!(back.spec_version, PAYLOAD_SPEC_VERSION);
        assert_eq!(back.entries.len(), 1);
        let e = &back.entries[0];
        assert_eq!(e.title, "GitHub");
        match &e.body {
            EntryBody::Login(l) => {
                assert_eq!(l.username, "octocat");
                assert_eq!(l.password, "s3cret");
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn rejected_unknown_entry_type() {
        use ciborium::value::{Integer, Value};

        let entry = ciborium::value::Value::Map(vec![
            (Value::Text("id".into()), Value::Text("x".into())),
            (Value::Text("title".into()), Value::Text("t".into())),
            (Value::Text("tags".into()), Value::Array(vec![])),
            (
                Value::Text("created_at".into()),
                Value::Integer(Integer::from(0i32)),
            ),
            (
                Value::Text("updated_at".into()),
                Value::Integer(Integer::from(0i32)),
            ),
            (
                Value::Text("type".into()),
                Value::Integer(Integer::from(99i32)),
            ),
            (Value::Text("data".into()), Value::Null),
        ]);
        let payload = ciborium::value::Value::Map(vec![
            (
                Value::Text("spec_version".into()),
                Value::Integer(Integer::from(PAYLOAD_SPEC_VERSION as i32)),
            ),
            (Value::Text("entries".into()), Value::Array(vec![entry])),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&payload, &mut bytes).unwrap();
        assert!(matches!(decode(&bytes), Err(Error::InvalidFormat(_))));
    }

    #[test]
    fn rejected_tampered_bytes() {
        let mut p = Payload::new();
        p.entries.push(sample_entry());
        let mut bytes = encode(&p).unwrap();
        let n = bytes.len();
        bytes[n - 5] ^= 0xFF;
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn rejects_unsupported_spec_version() {
        let p = Payload {
            spec_version: 99,
            entries: vec![],
        };
        let bytes = encode(&p).unwrap();
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn id_has_v4_bits() {
        let id = generate_id().unwrap();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"));
        assert_eq!(id.bytes().filter(|c| *c == b'-').count(), 4);
    }
}
