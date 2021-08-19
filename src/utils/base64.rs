use base64;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::error::{self, ResultExt};

#[derive(Debug, Clone)]
pub(crate) struct Base64Json<T: Serialize + DeserializeOwned> {
    pub(crate) value: T,
    pub(crate) encoded: String,
}

impl<T: Serialize + DeserializeOwned> Base64Json<T> {
    pub(crate) fn new(value: T) -> error::Result<Self> {
        let serialized = serde_json::to_string(&value)
            .kind(error::ErrorKind::InvalidState, "unable serialize.")?;

        let encoded = base64::encode_config(&serialized, base64::URL_SAFE_NO_PAD);

        Ok(Base64Json { value, encoded })
    }

    pub(crate) fn from_encoded(encoded: String) -> error::Result<Self> {
        let serialized = base64::decode_config(&encoded, base64::URL_SAFE_NO_PAD)
            .kind(error::ErrorKind::MessageMalformed, "unable decode.")?;

        let value: T = serde_json::from_slice(&serialized)
            .kind(error::ErrorKind::MessageMalformed, "unable deserialize.")?;

        Ok(Base64Json { value, encoded })
    }
}

impl<'de, T: Serialize + DeserializeOwned> Deserialize<'de> for Base64Json<T> {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded: String = Deserialize::deserialize(d)?;

        let res = Base64Json::from_encoded(encoded)
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;

        Ok(res)
    }
}

impl<T: Serialize + DeserializeOwned> Serialize for Base64Json<T> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Serialize::serialize(&self.encoded, s)
    }
}

pub(crate) trait Binary {
    fn as_slice(&self) -> &[u8];
    fn from_vec(vec: Vec<u8>) -> Self;
}

impl Binary for Vec<u8> {
    fn as_slice(&self) -> &[u8] {
        self
    }

    fn from_vec(vec: Vec<u8>) -> Self {
        vec
    }
}

impl<T: Binary> Base64Binary<T> {
    pub(crate) fn new(value: T) -> error::Result<Self> {
        let encoded = base64::encode_config(value.as_slice(), base64::URL_SAFE_NO_PAD);
        Ok(Base64Binary { value, encoded })
    }

    pub(crate) fn from_encoded(encoded: String) -> error::Result<Self> {
        let value = base64::decode_config(&encoded, base64::URL_SAFE_NO_PAD)
            .kind(error::ErrorKind::MessageMalformed, "unable decode.")?;

        Ok(Base64Binary {
            value: T::from_vec(value),
            encoded,
        })
    }
}

impl<'de, T: Binary> Deserialize<'de> for Base64Binary<T> {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded: String = Deserialize::deserialize(d)?;

        let res = Base64Binary::from_encoded(encoded)
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;

        Ok(res)
    }
}

impl<T: Binary> Serialize for Base64Binary<T> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Serialize::serialize(&self.encoded, s)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Base64Binary<T: Binary> {
    pub(crate) value: T,
    pub(crate) encoded: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, Clone)]
    struct DummyJson {
        val: String,
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    struct JsonWrapper {
        b64: Base64Json<DummyJson>,
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    struct BinaryWrapper {
        b64: Base64Binary<Vec<u8>>,
    }

    #[test]
    fn json_new_works() {
        let b64 = Base64Json::new(DummyJson {
            val: "dummy".into(),
        })
        .expect("new failed.");

        assert_eq!(b64.encoded, "eyJ2YWwiOiJkdW1teSJ9");
        assert_eq!(b64.value.val, "dummy");
    }

    #[test]
    fn json_from_encoded_works() {
        let b64 = Base64Json::<DummyJson>::from_encoded("eyJ2YWwiOiJkdW1teSJ9".into())
            .expect("from_encoded failed.");

        assert_eq!(b64.encoded, "eyJ2YWwiOiJkdW1teSJ9");
        assert_eq!(b64.value.val, "dummy");
    }

    #[test]
    fn json_serialize_works() {
        let dw = JsonWrapper {
            b64: Base64Json::new(DummyJson {
                val: "dummy".into(),
            })
            .expect("new failed."),
        };

        let ser = serde_json::to_string(&dw).expect("unable serialize");

        assert_eq!(ser, "{\"b64\":\"eyJ2YWwiOiJkdW1teSJ9\"}");
    }

    #[test]
    fn json_deserialize_works() {
        let dw: JsonWrapper =
            serde_json::from_str("{\"b64\":\"eyJ2YWwiOiJkdW1teSJ9\"}").expect("unable deserialize");

        assert_eq!(dw.b64.encoded, "eyJ2YWwiOiJkdW1teSJ9");
        assert_eq!(dw.b64.value.val, "dummy");
    }

    #[test]
    fn binary_new_works() {
        let b64 = Base64Binary::new(vec![1, 2, 3]).expect("new failed.");

        assert_eq!(b64.encoded, "AQID");
        assert_eq!(b64.value, vec![1, 2, 3]);
    }

    #[test]
    fn binary_from_encoded_works() {
        let b64 =
            Base64Binary::<Vec<u8>>::from_encoded("AQID".into()).expect("from_encoded failed.");

        assert_eq!(b64.encoded, "AQID");
        assert_eq!(b64.value, vec![1, 2, 3]);
    }

    #[test]
    fn binary_serialize_works() {
        let dw = BinaryWrapper {
            b64: Base64Binary::new(vec![1, 2, 3]).expect("new failed."),
        };

        let ser = serde_json::to_string(&dw).expect("unable serialize");

        assert_eq!(ser, "{\"b64\":\"AQID\"}");
    }

    #[test]
    fn binary_deserialize_works() {
        let dw: BinaryWrapper =
            serde_json::from_str("{\"b64\":\"AQID\"}").expect("unable deserialize");

        assert_eq!(dw.b64.encoded, "AQID");
        assert_eq!(dw.b64.value, vec![1, 2, 3]);
    }
}
