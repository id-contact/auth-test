use std::{collections::HashMap, convert::TryFrom, error::Error as StdError, fmt::Display};
use serde::Deserialize;
use id_contact_jwe::{SignKeyConfig, EncryptionKeyConfig};
use josekit::{
    jwe::{JweEncrypter},
    jws::{JwsSigner},
};

#[derive(Debug)]
pub enum Error {
    UnknownAttribute(String),
    YamlError(serde_yaml::Error),
    Json(serde_json::Error),
    JWT(id_contact_jwe::Error),
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

impl From<id_contact_jwe::Error> for Error {
    fn from(e: id_contact_jwe::Error) -> Error {
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

// This tryfrom can be removed once try_from for fields lands in serde
impl TryFrom<RawConfig> for Config {
    type Error = Error;
    fn try_from(config: RawConfig) -> Result<Config, Error> {
        Ok(Config {
            server_url: config.server_url,
            attributes: config.attributes,
            with_session: config.with_session,
            encrypter: Box::<dyn JweEncrypter>::try_from(config.encryption_pubkey)?,
            signer: Box::<dyn JwsSigner>::try_from(config.signing_privkey)?,
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
