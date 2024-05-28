use crate::{base64, spec::{hash_leaf, serialize_timestamped_entry}};
use rasn::der;
use rasn_pkix::{Certificate, TbsCertificate};
use serde::{Deserialize, Serialize};

// JSON Types for API Endpoints

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AddChainInput {
    // chain:  An array of base64-encoded certificates.  The first
    // element is the end-entity certificate; the second chains to the
    // first and so on to the last, which is either the root
    // certificate or a certificate that chains to a known root
    // certificate.
    pub chain: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AddChainOutput {
    //  sct_version:  The version of the SignedCertificateTimestamp
    //     structure, in decimal.  A compliant v1 implementation MUST NOT
    //     expect this to be 0 (i.e., v1).
    // This should always be "V1"
    pub sct_version: String,

    //  id:  The log ID, base64 encoded.  Since log clients who request an
    //     SCT for inclusion in TLS handshakes are not required to verify
    //     it, we do not assume they know the ID of the log.
    pub id: [u8; 32],

    //  timestamp:  The SCT timestamp, in decimal.
    pub timestamp: u64,

    //  extensions:  An opaque type for future expansion.  It is likely
    //     that not all participants will need to understand data in this
    //     field.  Logs should set this to the empty string.  Clients
    //     should decode the base64-encoded data and include it in the
    //     SCT.
    pub extensions: String,

    //  signature:  The SCT signature, base64 encoded.
    pub signature: String,
}

pub struct AddChainInputParsed {
    pub chain: Vec<Certificate>,
}

impl From<AddChainInput> for AddChainInputParsed {
    fn from(input: AddChainInput) -> Self {
        let chain = input
            .chain
            .iter()
            .map(|cert| {
                der::decode(&base64::decode(cert).expect("Failed to decode base64 certificate"))
                    .expect("Failed to parse certificate")
            })
            .collect();
        AddChainInputParsed { chain }
    }
}

/// All the information needed to serialize or validate anything
#[derive(Debug)]
pub struct UnsequencedEntry {
    pub timestamp: u64,
    pub certs: Cert,
    pub raw_certs: Vec<Vec<u8>>,
    pub return_path: Option<tokio::sync::oneshot::Sender<Entry>>,
}

#[derive(Debug)]
pub struct Entry {
    pub timestamp: u64,
    pub certs: Cert,
    pub raw_certs: Vec<Vec<u8>>,
    pub return_path: Option<tokio::sync::oneshot::Sender<Entry>>,

    /// The spec only gives us 40 bits to store this.
    /// Hopes and prayers ensure that it fits.
    pub leaf_index: u64,
}

#[derive(Debug)]
pub enum Cert {
    X509 {
        cert: Certificate,
        chain: Vec<Certificate>,
    },
    Precert {
        cert: TbsCertificate,
        chain: Vec<Certificate>,
    },
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Failed to decode base64 certificate")]
    Base64Decode(#[from] base64::DecodeError),
    // #[error("Failed to parse certificate")]
    // ParseCertificate(#[from] rasn::error::DecodeError),
}

pub struct LeafTile {
    index: u64,
    serialized_timestamp_entries: Vec<Vec<u8>>,
    hashes: Vec<[u8; 32]>,
}

impl LeafTile {
    pub fn add_entry(&mut self, entry: Entry) {
        self.serialized_timestamp_entries.push(serialize_timestamped_entry(&entry));
        self.hashes.push(hash_leaf(&entry));
    }
}

pub struct NodeTile {
    index: u64,
    hashes: Vec<[u8; 32]>,
}

pub struct Tiles {
    l0: LeafTile,
    l1: Option<NodeTile>,
    l2: Option<NodeTile>,
    l3: Option<NodeTile>,
    l4: Option<NodeTile>,
}

impl Tiles {
    pub fn add_entries(&mut self, entries: Vec<Entry>) {
        for entry in entries {
            self.l0.add_entry(entry);
        }
    }
}