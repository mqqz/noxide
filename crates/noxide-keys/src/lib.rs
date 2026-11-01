//! Host key material and its only operations. Callers receive MACs, sealed
//! envelopes and opened plaintexts, never key bytes.
//!
//! [`Keys::Local`] holds the material in this process, for operator commands.
//! [`Keys::Remote`] asks a key service over an inherited socket, so a compromised
//! serving process can use the keys while it runs but cannot read them.
#![forbid(unsafe_code)]
mod material;
mod service;

pub use material::{KeyMaterial, TokenDomain};
pub use service::{KeyClient, serve};

use anyhow::Result;
use serde::{Deserialize, Serialize};

pub enum Keys {
    Local(KeyMaterial),
    Remote(KeyClient),
}

impl Keys {
    pub fn incarnation(&self) -> &str {
        match self {
            Self::Local(material) => material.incarnation(),
            Self::Remote(client) => client.incarnation(),
        }
    }
    pub fn signing_edit_key(&self) -> Result<u32> {
        match self {
            Self::Local(material) => material.signing_edit_key(),
            Self::Remote(client) => client.signing_edit_key(),
        }
    }
    pub fn seal(&self, domain: TokenDomain, plaintext: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Local(material) => material.seal(domain, plaintext),
            Self::Remote(client) => client.seal(domain, plaintext),
        }
    }
    pub fn open(&self, domain: TokenDomain, envelope: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Local(material) => material.open(domain, envelope),
            Self::Remote(client) => client.open(domain, envelope),
        }
    }
    pub fn csrf(&self, subject: &str) -> Result<[u8; 32]> {
        match self {
            Self::Local(material) => Ok(material.csrf(subject)),
            Self::Remote(client) => client.csrf(subject),
        }
    }
    pub fn edit_mac(&self, key: u32, resource: u32, id: u64, version: u64) -> Result<[u8; 32]> {
        match self {
            Self::Local(material) => material.edit_mac(key, resource, id, version),
            Self::Remote(client) => client.edit_mac(key, resource, id, version),
        }
    }
}

/// Only local material has a serialized form; a remote handle has no bytes to write.
impl Serialize for Keys {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Local(material) => material.serialize(serializer),
            Self::Remote(_) => Err(serde::ser::Error::custom("remote keys have no bytes")),
        }
    }
}
impl<'de> Deserialize<'de> for Keys {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        KeyMaterial::deserialize(deserializer).map(Self::Local)
    }
}
