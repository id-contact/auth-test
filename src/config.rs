use std::{collections::HashMap, convert::TryFrom, error::Error as StdError, fmt::Display};
use serde::Deserialize;

use josekit::{
    jwe::{JweEncrypter, ECDH_ES, RSA_OAEP},
    jws::{JwsSigner, ES256, RS256},
};

#[derive(Debug)]
pub enum Error {
    UnknownAttribute(String),
    YamlError(serde_yaml::Error),
    Json(serde_json::Error),
    JWT(josekit::JoseError),
}

impl From<serde_yaml::Error> for Error {
    fn from(e: serde_yaml::Error) -> Error {
        Error::YamlError(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::Json(e)
    }
}

impl From<josekit::JoseError> for Error {
    fn from(e: josekit::JoseError) -> Error {
        Error::JWT(e)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnknownAttribute(a) => f.write_fmt(format_args!("Unknown attribute {}", a)),
            Error::YamlError(e) => e.fmt(f),
            Error::Json(e) => e.fmt(f),
            Error::JWT(e) => e.fmt(f),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::YamlError(e) => Some(e),
            Error::Json(e) => Some(e),
            Error::JWT(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Deserialize, Debug)]
struct InnerKeyConfig {
    key: String,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
enum EncryptionKeyConfig {
    RSA(InnerKeyConfig),
    EC(InnerKeyConfig),
}

impl EncryptionKeyConfig {
    fn to_encrypter(&self) -> Result<Box<dyn JweEncrypter>, Error> {
        match self {
            EncryptionKeyConfig::RSA(key) => Ok(Box::new(RSA_OAEP.encrypter_from_pem(&key.key)?)),
            EncryptionKeyConfig::EC(key) => Ok(Box::new(ECDH_ES.encrypter_from_pem(&key.key)?)),
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
enum SignKeyConfig {
    RSA(InnerKeyConfig),
    EC(InnerKeyConfig),
}

impl SignKeyConfig {
    fn to_signer(&self) -> Result<Box<dyn JwsSigner>, Error> {
        match self {
            SignKeyConfig::RSA(key) => Ok(Box::new(RS256.signer_from_pem(&key.key)?)),
            SignKeyConfig::EC(key) => Ok(Box::new(ES256.signer_from_pem(&key.key)?)),
        }
    }
}

#[derive(Deserialize, Debug)]
struct RawConfig {
    server_url: String,
    attributes: HashMap<String, String>,
    with_session: bool,
    encryption_pubkey: EncryptionKeyConfig,
    signing_privkey: SignKeyConfig,
}

#[derive(Debug, Deserialize)]
#[serde(try_from = "RawConfig")]
pub struct Config {
    server_url: String,
    attributes: HashMap<String, String>,
    with_session: bool,
    encrypter: Box<dyn JweEncrypter>,
    signer: Box<dyn JwsSigner>,
}

impl TryFrom<RawConfig> for Config {
    type Error = Error;
    fn try_from(config: RawConfig) -> Result<Config, Error> {
        Ok(Config {
            server_url: config.server_url,
            attributes: config.attributes,
            with_session: config.with_session,
            encrypter: config.encryption_pubkey.to_encrypter()?,
            signer: config.signing_privkey.to_signer()?,
        })
    }
}

impl Config {
    pub fn verify_attributes(&self, attributes:&[String]) -> Result<(), Error> {
        for attribute in attributes.iter() {
            self.attributes.get(attribute).ok_or_else(|| Error::UnknownAttribute(attribute.clone()))?;
        }

        Ok(())
    }

    pub fn map_attributes(&self, attributes: &[String]) -> Result<HashMap<String, String>, Error> {
        let mut result: HashMap<String, String> = HashMap::new();
        for attribute in attributes.iter() {
            result.insert(attribute.clone(), self.attributes.get(attribute).ok_or_else(|| Error::UnknownAttribute(attribute.clone()))?.clone());
        }

        Ok(result)
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    pub fn with_session(&self) -> bool {
        self.with_session
    }

    pub fn encrypter(&self) -> &dyn JweEncrypter {
        self.encrypter.as_ref()
    }

    pub fn signer(&self) -> &dyn JwsSigner {
        self.signer.as_ref()
    }

    pub fn from_string(config: &str) -> Result<Config, Error> {
        Ok(serde_yaml::from_str(config)?)
    }

    pub fn from_reader<T: std::io::Read>(reader: T) -> Result<Config, Error> {
        Ok(serde_yaml::from_reader(reader)?)
    }
}
