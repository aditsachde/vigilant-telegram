//! Stuff in this file is spec defined behavior, either in
//! RFC6962 or in C2SP/sunlight.md
//! As of 3/25/24, nothing has been verified to be spec compliant
//!
//! Things that need to be done according to spec:
//! 1. Signing the SCT
//! 2. Serializing the CT extensions
//! 3. Serializing the TimestampedEntry
//! 4. Hashing the leaf TimestampedEntry
//! 5. hashing the node entries
//!
//! Things that need to be done to return a valid SCT:
//! 1. Parse and validate the input certificates
//! 2. Create an unsequenced timestamped entry
//! 3. Put the timestamped entry in the sequencer blender
//! 4. Upload the sequenced tiles to KV
//! 5. Return the sequenced timestamped entry
//! 6. Sign and return the SCT signature

use crate::{
    base64,
    ds::{Cert, Entry},
};
use p256::{ecdsa::SigningKey, SecretKey};
use rasn::{
    cer, der,
    types::{ObjectIdentifier, Oid},
};
use rasn_pkix::{Extension, Extensions};
use sha2::{Digest, Sha256};

/// https://datatracker.ietf.org/doc/html/rfc6962#section-3.4
pub fn serialize_timestamped_entry(entry: &Entry) -> Vec<u8> {
    // struct {
    //     uint64 timestamp;
    //     LogEntryType entry_type;
    //     select(entry_type) {
    //         case x509_entry: ASN.1Cert;
    //         case precert_entry: PreCert;
    //     } signed_entry;
    //     CtExtensions extensions;
    // } TimestampedEntry;
    let mut buf = Vec::new();
    // The first 8 bytes are the timestamp encoded as big endian.
    buf.extend_from_slice(&entry.timestamp.to_be_bytes());
    // The next two bytes are the entry type encoded as big endian,
    // which is 0 for X509 certificates and 1 for precertificates.
    match &entry.certs {
        Cert::X509 { cert, .. } => {
            buf.push(0x00);
            buf.push(0x00);
            // Then, we encode the following data
            // opaque ASN.1Cert<1..2^24-1>;
            let cert = der::encode(cert).unwrap();
            let len = cert.len();
            buf.push(((len >> 16) & 0xFF) as u8);
            buf.push(((len >> 8) & 0xFF) as u8);
            buf.push((len & 0xFF) as u8);
            buf.extend_from_slice(&cert);
        }
        Cert::Precert { cert, chain } => {
            buf.push(0x00);
            buf.push(0x01);
            // Then, we encode the following data
            // opaque TBSCertificate<1..2^24-1>;

            // struct {
            //   opaque issuer_key_hash[32];
            //   TBSCertificate tbs_certificate;
            // } PreCert;

            // TODO: we need to check if this is a preissuer certificate,
            // in which case we should use chain[1] instead of chain[0]
            // TODO: It is unclear if we should remove the precert posion
            // extension here, or when the conversion to precert is done
            let mut defanged = cert.clone();
            if let Some(exts) = defanged.extensions.as_mut() {
                exts.retain(|ext| {
                    // Use new unchecked here because this is a static OID that is googlePrecertificatePoison
                    ext.extn_id != Oid::new_unchecked(&[1, 3, 6, 1, 4, 1, 11129, 2, 4, 3])
                })
            }

            // The issuer key hash is the DER encoded SubjectPublicKeyInfo
            // of the issuer certificate of the precert.
            let spki = der::encode(&chain[0].tbs_certificate.subject_public_key_info).unwrap();
            // Get the SHA256 hash of the SPKI
            let hash: [u8; 32] = Sha256::digest(spki).into();
            buf.extend_from_slice(&hash);

            let cert = der::encode(&defanged).unwrap();
            let len = cert.len();
            buf.push(((len >> 16) & 0xFF) as u8);
            buf.push(((len >> 8) & 0xFF) as u8);
            buf.push((len & 0xFF) as u8);
            buf.extend_from_slice(&cert);
        }
    }
    // Finally, we encode the extensions
    // This is prefixed with a 2 byte length field
    // which is always 8 bytes.
    buf.push(0x00);
    buf.push(0x08);
    buf.extend(serialize_ct_extensions(entry));
    // Return the vector
    buf
}

///https://github.com/C2SP/C2SP/blob/main/sunlight.md#log-entries
pub fn serialize_tile_leaf(entry: &Entry) -> Vec<u8> {
    let mut buf = serialize_timestamped_entry(entry);
    if let Cert::Precert { cert, chain } = &entry.certs {
        // If this is a precert, we include the following data
        // struct {
        //   ASN.1Cert pre_certificate;
        //   opaque PrecertificateSigningCertificate<0..2^24-1>;
        // } PreCertExtraData;

        // opaque ASN.1Cert<1..2^24-1>;
        // In this case, we're including the actual precert, not just the TbsCertificate
        let raw_cert = &entry.raw_certs[0];
        let len = raw_cert.len();
        buf.push(((len >> 16) & 0xFF) as u8);
        buf.push(((len >> 8) & 0xFF) as u8);
        buf.push((len & 0xFF) as u8);
        buf.extend_from_slice(raw_cert);

        // TODO: we need to check if this is a preissuer certificate,
        // and only then should we encode in the following data

        // opaque PrecertificateSigningCertificate<0..2^24-1>;
        // let enc = der::encode(&chain[0]).unwrap();
        // let len = enc.len();
        // buf.push(((len >> 16) & 0xFF) as u8);
        // buf.push(((len >> 8) & 0xFF) as u8);
        // buf.push((len & 0xFF) as u8);
        // buf.extend_from_slice(&enc);

        // If its not a preissuer, we still need to include the length bytes
        // to signify that this field is intentionally empty.
        // The length is 24 bits, so we can just add 3 zero bytes.
        buf.extend_from_slice(&[0x00, 0x00, 0x00]);
    };
    buf
}

/// https://github.com/C2SP/C2SP/blob/main/sunlight.md#sct-extension
pub fn serialize_ct_extensions(entry: &Entry) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8);
    // The first byte signifies that this is a leaf_index extension,
    // which is encoded as 0.
    buf.push(0x00);
    // The next two bytes are the length of the opaque extension_data.
    // Since we are encoding a 40 bit leaf_index, this is always 5.
    buf.push(0x00);
    buf.push(0x05);
    // The last five bytes are the leaf index encoded as big endian.
    let li = entry.leaf_index;
    buf.push(((li >> 32) & 0xFF) as u8);
    buf.push(((li >> 24) & 0xFF) as u8);
    buf.push(((li >> 16) & 0xFF) as u8);
    buf.push(((li >> 8) & 0xFF) as u8);
    buf.push((li & 0xFF) as u8);
    // Return the vector
    buf
}

// https://datatracker.ietf.org/doc/html/rfc6962#section-2.1
pub fn hash_leaf(entry: &Entry) -> [u8; 32] {
    let mut hash = Sha256::new();
    // The formula for a leaf hash is: MTH({d(0)}) = SHA-256(0x00 || d(0)).
    hash.update([0x00]);

    // The RFC defines the hash as that of a MerkleTreeLeaf, which is really
    // just a TimeStampedEntry with a version number and leaf type.

    // struct {
    //     Version version;
    //     MerkleLeafType leaf_type;
    //     select (leaf_type) {
    //         case timestamped_entry: TimestampedEntry;
    //     }
    // } MerkleTreeLeaf;

    // enum { v1(0), (255) }
    //      Version;
    hash.update([0x00]);

    // enum { timestamped_entry(0), (255) }
    //      MerkleLeafType;
    hash.update([0x00]);

    // select (leaf_type) {
    //     case timestamped_entry: TimestampedEntry;
    // }
    hash.update(serialize_timestamped_entry(entry));

    hash.finalize().into()
}

// TODO: I don't think this is actually wrong, but it needs unit tests
pub fn hash_node(children: Vec<[u8; 32]>) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update([0x01]);

    for child in children {
        hash.update(child);
    }
    hash.finalize().into()
}

// https://datatracker.ietf.org/doc/html/rfc6962#section-3.2
pub fn sign_sct(entry: &Entry, key: &SecretKey) -> Vec<u8> {
    // This is a hazmat function because the secret key needs to be actually random!
    use ecdsa::hazmat::sign_prehashed_rfc6979;

    // We need to digitally sign the following structure
    // digitally-signed struct {
    //     Version sct_version;
    //     SignatureType signature_type = certificate_timestamp;
    //     uint64 timestamp;
    //     LogEntryType entry_type;
    //     select(entry_type) {
    //         case x509_entry: ASN.1Cert;
    //         case precert_entry: PreCert;
    //     } signed_entry;
    //    CtExtensions extensions;
    // };

    // enum { v1(0), (255) }
    //     Version;

    // enum { certificate_timestamp(0), tree_hash(1), (255) }
    // SignatureType;

    // Version v1; SignatureType certificate_timestamp
    let mut buf = vec![0x00, 0x00];
    // The format of the rest actually just matches that of the timestamped entry
    buf.extend(serialize_timestamped_entry(entry));

    // Calculate the hash of the structure
    let digest = Sha256::digest(buf);

    let signature =
        sign_prehashed_rfc6979::<p256::NistP256, Sha256>(&key.to_nonzero_scalar(), &digest, &[])
            // This unwrap needs to be removed
            .unwrap()
            .0
            // The signature is encded in DER format as per the spec
            .to_der()
            .to_bytes();

    // We now have the signature, but it needs to be properly formatted
    // The format of the signature should be DigitallySigned
    // https://datatracker.ietf.org/doc/html/rfc5246#section-4.7

    // struct {
    //     SignatureAndHashAlgorithm algorithm;
    //     opaque signature<0..2^16-1>;
    //  } DigitallySigned;

    // struct {
    //       HashAlgorithm hash;
    //       SignatureAlgorithm signature;
    // } SignatureAndHashAlgorithm;

    // enum {
    //     none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
    //     sha512(6), (255)
    // } HashAlgorithm;
    // The hash algorithm is always SHA256
    let hash = 0x04;

    // enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
    //   SignatureAlgorithm;
    // The signature algorithm is always ECDSA
    let sig = 0x03;

    // The first two bytes of the buffer are the hash and sig algorithms
    let mut buf = vec![hash, sig];

    // The next two bytes are the length of the signature
    let len = signature.len();
    buf.push(((len >> 8) & 0xFF) as u8);
    buf.push((len & 0xFF) as u8);

    // The rest of the bytes are the signature itself
    buf.extend(&*signature);

    buf
}

fn sign_checkpoint(timestamp: u64, key: &SecretKey) -> String {
    todo!()
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::*;

    // Borrowed from sunlight, these are just the certs for rome.ct.filippo.io
    const TESTLEAF: &str = "MIIEJjCCAw6gAwIBAgISA9YVxv2Lcc/y6IhrW5svQmHPMA0GCSqGSIb3DQEBCwUAMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJSMzAeFw0yMzExMTUxMDE5MTFaFw0yNDAyMTMxMDE5MTBaMB0xGzAZBgNVBAMTEnJvbWUuY3QuZmlsaXBwby5pbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMufQMpi+5cCSw8a6D2se6bjTR6Vpcm5kr5b1UHaJZVdM4tOCy66d3iO9LcKYwIdXJJD1TbtzAuLlRCWa1HNlGSjggIUMIICEDAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFIiqDtb1Rz6Y9iVID4JBRl36tE47MB8GA1UdIwQYMBaAFBQusxe3WFbLrlAJQOYfr52LFMLGMFUGCCsGAQUFBwEBBEkwRzAhBggrBgEFBQcwAYYVaHR0cDovL3IzLm8ubGVuY3Iub3JnMCIGCCsGAQUFBzAChhZodHRwOi8vcjMuaS5sZW5jci5vcmcvMB0GA1UdEQQWMBSCEnJvbWUuY3QuZmlsaXBwby5pbzATBgNVHSAEDDAKMAgGBmeBDAECATCCAQQGCisGAQQB1nkCBAIEgfUEgfIA8AB2AEiw42vapkc0D+VqAvqdMOscUgHLVt0sgdm7v6s52IRzAAABi9K04WIAAAQDAEcwRQIhAIjFeq4LZpEUNCTtVu1s3yURyaX18TRp4qjt02A2FYHEAiBWQxxfEsyYUFuDOFIYSh6q6MA9m2YenRmL7FqzgpMvpAB2ADtTd3U+LbmAToswWwb+QDtn2E/D9Me9AA0tcm/h+tQXAAABi9K0418AAAQDAEcwRQIhAJfS1HrW24DPJJCzwZ+Xgo4jX/o6nsXNVRuOrrqoFjBmAiAi53R5tlmS94uXLnUyX6+ULDxwCuSRSb23iEidzugiVDANBgkqhkiG9w0BAQsFAAOCAQEAc0EXBRfCal3xyXZ60DJspRf66ulLpVii1BPvcf0PWWGC/MCjbY2xwz+1p6fePMSMrUJpOTtP5L52bZNQBptq6oKSOKGpVn8eIaVqNPeJsYCuzL5tKnzfhBoyIs9tqc8U7JwZuIyCIFsxd5eDNLSNyphX9+jxATorpFJ8RYibzjmBkDjRSl6T2f32Qy4AKy2FJe2yryJjdiDHqzT3SoTYcJp/2wWklYFMtBV/j4qTGyFiVdVZ1GQUhHvlw1iVqXLHe8cVQoSc+iStlDxeFWEuKnHRTtpfNz+KzP15R13C6CBswODDjqH2HCS2OKhyENB6SF7KhhD5/hMVyj6UWq9pDw==";
    const TESTPRECERT: &str = "MIIDMzCCAhugAwIBAgISA9YVxv2Lcc/y6IhrW5svQmHPMA0GCSqGSIb3DQEBCwUAMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJSMzAeFw0yMzExMTUxMDE5MTFaFw0yNDAyMTMxMDE5MTBaMB0xGzAZBgNVBAMTEnJvbWUuY3QuZmlsaXBwby5pbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMufQMpi+5cCSw8a6D2se6bjTR6Vpcm5kr5b1UHaJZVdM4tOCy66d3iO9LcKYwIdXJJD1TbtzAuLlRCWa1HNlGSjggEhMIIBHTAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFIiqDtb1Rz6Y9iVID4JBRl36tE47MB8GA1UdIwQYMBaAFBQusxe3WFbLrlAJQOYfr52LFMLGMFUGCCsGAQUFBwEBBEkwRzAhBggrBgEFBQcwAYYVaHR0cDovL3IzLm8ubGVuY3Iub3JnMCIGCCsGAQUFBzAChhZodHRwOi8vcjMuaS5sZW5jci5vcmcvMB0GA1UdEQQWMBSCEnJvbWUuY3QuZmlsaXBwby5pbzATBgNVHSAEDDAKMAgGBmeBDAECATATBgorBgEEAdZ5AgQDAQH/BAIFADANBgkqhkiG9w0BAQsFAAOCAQEAk4K63mYRtOqH2LprGfBDIXnOXGt7wicdyBD2Zh5tkqMBB0XulcAi94IUfEOBSfIIzZ5lTh8WvAB6RxMGXYf8Qx4dHCP1McpMvkOJNEz9cHVjoBxx8asdAsV6d+av3MsK83n/fnN6looyUoDz09AZNvmlR74HCmpgLydMMv8ugdiPjRlYLaKy8wiA+HpX2rb4oWJ9kSD7dxuu6+NqPi4qWVsopQKBMcYEhCfQN26tcm2X3jebcwE3TFNxhK5RcRTWMO3i5AtaUZDT4bWUTFTHP8668wvCpI8MyfIlVdlUv3BOnyjvr/zpSBb/SfbyE0yiUBKhxl5z3+LImTNwxbc5sg==";
    const TESTINTERMEDIATE: &str = "MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAwTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAwWhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cPR5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdxsxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8ZutmNHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxgZ3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaAFHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6WPTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wlikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQzCkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BImlJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1OyK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90IdshCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6ZvMldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqXnLRbwHOoq7hHwg==";
    const TESTROOT: &str = "MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAwTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygch77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6UA5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sWT8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyHB5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UCB5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUvKBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWnOlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTnjh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbwqHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CIrU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkqhkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZLubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KKNFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7UrTkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdCjNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVcoyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPAmRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57demyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=";

    fn to_cert(cert: &str) -> rasn_pkix::Certificate {
        rasn::der::decode(&base64::decode(cert).unwrap()).unwrap()
    }

    #[test]
    fn test_serialize_timestamped_entry_cert() {
        let entry = Entry {
            timestamp: 1712007656124,
            certs: Cert::X509 {
                cert: to_cert(TESTLEAF),
                chain: vec![to_cert(TESTINTERMEDIATE), to_cert(TESTROOT)],
            },
            raw_certs: vec![
                base64::decode(TESTLEAF).unwrap(),
                base64::decode(TESTINTERMEDIATE).unwrap(),
                base64::decode(TESTROOT).unwrap(),
            ],
            return_path: None,
            leaf_index: 1,
        };

        let serialized = serialize_timestamped_entry(&entry);
        // Test value is from sunlight ctlog_test::testSubmit,
        // with leaf index of 1 and initial timestamp of 1712007656124
        assert_eq!(
            base64::encode(serialized),
            "AAABjpubsrwAAAAEKjCCBCYwggMOoAMCAQICEgPWFcb9i3HP8uiIa1ubL0JhzzANBgkqhkiG9w0BAQsFADAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5jcnlwdDELMAkGA1UEAxMCUjMwHhcNMjMxMTE1MTAxOTExWhcNMjQwMjEzMTAxOTEwWjAdMRswGQYDVQQDExJyb21lLmN0LmZpbGlwcG8uaW8wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATLn0DKYvuXAksPGug9rHum400elaXJuZK+W9VB2iWVXTOLTgsuund4jvS3CmMCHVySQ9U27cwLi5UQlmtRzZRko4ICFDCCAhAwDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSIqg7W9Uc+mPYlSA+CQUZd+rROOzAfBgNVHSMEGDAWgBQULrMXt1hWy65QCUDmH6+dixTCxjBVBggrBgEFBQcBAQRJMEcwIQYIKwYBBQUHMAGGFWh0dHA6Ly9yMy5vLmxlbmNyLm9yZzAiBggrBgEFBQcwAoYWaHR0cDovL3IzLmkubGVuY3Iub3JnLzAdBgNVHREEFjAUghJyb21lLmN0LmZpbGlwcG8uaW8wEwYDVR0gBAwwCjAIBgZngQwBAgEwggEEBgorBgEEAdZ5AgQCBIH1BIHyAPAAdgBIsONr2qZHNA/lagL6nTDrHFIBy1bdLIHZu7+rOdiEcwAAAYvStOFiAAAEAwBHMEUCIQCIxXquC2aRFDQk7VbtbN8lEcml9fE0aeKo7dNgNhWBxAIgVkMcXxLMmFBbgzhSGEoequjAPZtmHp0Zi+xas4KTL6QAdgA7U3d1Pi25gE6LMFsG/kA7Z9hPw/THvQANLXJv4frUFwAAAYvStONfAAAEAwBHMEUCIQCX0tR61tuAzySQs8Gfl4KOI1/6Op7FzVUbjq66qBYwZgIgIud0ebZZkveLly51Ml+vlCw8cArkkUm9t4hInc7oIlQwDQYJKoZIhvcNAQELBQADggEBAHNBFwUXwmpd8cl2etAybKUX+urpS6VYotQT73H9D1lhgvzAo22NscM/taen3jzEjK1CaTk7T+S+dm2TUAabauqCkjihqVZ/HiGlajT3ibGArsy+bSp834QaMiLPbanPFOycGbiMgiBbMXeXgzS0jcqYV/fo8QE6K6RSfEWIm845gZA40Upek9n99kMuACsthSXtsq8iY3Ygx6s090qE2HCaf9sFpJWBTLQVf4+KkxshYlXVWdRkFIR75cNYlalyx3vHFUKEnPokrZQ8XhVhLipx0U7aXzc/isz9eUddwuggbMDgw46h9hwktjiochDQekheyoYQ+f4TFco+lFqvaQ8ACAAABQAAAAAB"
        );
    }

    #[test]
    fn test_serialize_timestamped_entry_precert() {
        let entry = Entry {
            timestamp: 1712008236630,
            certs: Cert::Precert {
                cert: to_cert(TESTPRECERT).tbs_certificate,
                chain: vec![to_cert(TESTINTERMEDIATE), to_cert(TESTROOT)],
            },
            raw_certs: vec![
                base64::decode(TESTPRECERT).unwrap(),
                base64::decode(TESTINTERMEDIATE).unwrap(),
                base64::decode(TESTROOT).unwrap(),
            ],
            return_path: None,
            leaf_index: 1,
        };

        let serialized = serialize_timestamped_entry(&entry);
        // Test value is from sunlight ctlog_test::testSubmit,
        // with leaf index of 1 and initial timestamp of 1712008236630
        assert_eq!(
            base64::encode(serialized),
            "AAABjpukjlYAAY0CU2yIdIK8NP9U5B0rplm/hbNBoKIK+ttYE9z7zyhtAAIKMIICBqADAgECAhID1hXG/Ytxz/LoiGtbmy9CYc8wDQYJKoZIhvcNAQELBQAwMjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxCzAJBgNVBAMTAlIzMB4XDTIzMTExNTEwMTkxMVoXDTI0MDIxMzEwMTkxMFowHTEbMBkGA1UEAxMScm9tZS5jdC5maWxpcHBvLmlvMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEy59AymL7lwJLDxroPax7puNNHpWlybmSvlvVQdollV0zi04LLrp3eI70twpjAh1ckkPVNu3MC4uVEJZrUc2UZKOCAQwwggEIMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUiKoO1vVHPpj2JUgPgkFGXfq0TjswHwYDVR0jBBgwFoAUFC6zF7dYVsuuUAlA5h+vnYsUwsYwVQYIKwYBBQUHAQEESTBHMCEGCCsGAQUFBzABhhVodHRwOi8vcjMuby5sZW5jci5vcmcwIgYIKwYBBQUHMAKGFmh0dHA6Ly9yMy5pLmxlbmNyLm9yZy8wHQYDVR0RBBYwFIIScm9tZS5jdC5maWxpcHBvLmlvMBMGA1UdIAQMMAowCAYGZ4EMAQIBAAgAAAUAAAAAAQ=="
        );
    }

    #[test]
    fn test_serialize_tile_leaf_cert() {
        let entry = Entry {
            timestamp: 1712007656124,
            certs: Cert::X509 {
                cert: to_cert(TESTLEAF),
                chain: vec![to_cert(TESTINTERMEDIATE), to_cert(TESTROOT)],
            },
            raw_certs: vec![
                base64::decode(TESTLEAF).unwrap(),
                base64::decode(TESTINTERMEDIATE).unwrap(),
                base64::decode(TESTROOT).unwrap(),
            ],
            return_path: None,
            leaf_index: 1,
        };

        let serialized = serialize_tile_leaf(&entry);
        // Test value is from sunlight ctlog_test::testSubmit,
        // with leaf index of 1 and initial timestamp of 1712007656124
        assert_eq!(
            base64::encode(serialized),
            "AAABjpubsrwAAAAEKjCCBCYwggMOoAMCAQICEgPWFcb9i3HP8uiIa1ubL0JhzzANBgkqhkiG9w0BAQsFADAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5jcnlwdDELMAkGA1UEAxMCUjMwHhcNMjMxMTE1MTAxOTExWhcNMjQwMjEzMTAxOTEwWjAdMRswGQYDVQQDExJyb21lLmN0LmZpbGlwcG8uaW8wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATLn0DKYvuXAksPGug9rHum400elaXJuZK+W9VB2iWVXTOLTgsuund4jvS3CmMCHVySQ9U27cwLi5UQlmtRzZRko4ICFDCCAhAwDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSIqg7W9Uc+mPYlSA+CQUZd+rROOzAfBgNVHSMEGDAWgBQULrMXt1hWy65QCUDmH6+dixTCxjBVBggrBgEFBQcBAQRJMEcwIQYIKwYBBQUHMAGGFWh0dHA6Ly9yMy5vLmxlbmNyLm9yZzAiBggrBgEFBQcwAoYWaHR0cDovL3IzLmkubGVuY3Iub3JnLzAdBgNVHREEFjAUghJyb21lLmN0LmZpbGlwcG8uaW8wEwYDVR0gBAwwCjAIBgZngQwBAgEwggEEBgorBgEEAdZ5AgQCBIH1BIHyAPAAdgBIsONr2qZHNA/lagL6nTDrHFIBy1bdLIHZu7+rOdiEcwAAAYvStOFiAAAEAwBHMEUCIQCIxXquC2aRFDQk7VbtbN8lEcml9fE0aeKo7dNgNhWBxAIgVkMcXxLMmFBbgzhSGEoequjAPZtmHp0Zi+xas4KTL6QAdgA7U3d1Pi25gE6LMFsG/kA7Z9hPw/THvQANLXJv4frUFwAAAYvStONfAAAEAwBHMEUCIQCX0tR61tuAzySQs8Gfl4KOI1/6Op7FzVUbjq66qBYwZgIgIud0ebZZkveLly51Ml+vlCw8cArkkUm9t4hInc7oIlQwDQYJKoZIhvcNAQELBQADggEBAHNBFwUXwmpd8cl2etAybKUX+urpS6VYotQT73H9D1lhgvzAo22NscM/taen3jzEjK1CaTk7T+S+dm2TUAabauqCkjihqVZ/HiGlajT3ibGArsy+bSp834QaMiLPbanPFOycGbiMgiBbMXeXgzS0jcqYV/fo8QE6K6RSfEWIm845gZA40Upek9n99kMuACsthSXtsq8iY3Ygx6s090qE2HCaf9sFpJWBTLQVf4+KkxshYlXVWdRkFIR75cNYlalyx3vHFUKEnPokrZQ8XhVhLipx0U7aXzc/isz9eUddwuggbMDgw46h9hwktjiochDQekheyoYQ+f4TFco+lFqvaQ8ACAAABQAAAAAB"
        );
    }

    #[test]
    fn test_serialize_tile_leaf_precert() {
        let entry = Entry {
            timestamp: 1712007656131,
            certs: Cert::Precert {
                cert: to_cert(TESTPRECERT).tbs_certificate,
                chain: vec![to_cert(TESTINTERMEDIATE), to_cert(TESTROOT)],
            },
            raw_certs: vec![
                base64::decode(TESTPRECERT).unwrap(),
                base64::decode(TESTINTERMEDIATE).unwrap(),
                base64::decode(TESTROOT).unwrap(),
            ],
            return_path: None,
            leaf_index: 1,
        };

        let serialized = serialize_tile_leaf(&entry);
        // Test value is from sunlight ctlog_test::testSubmit,
        // with leaf index of 1 and initial timestamp of 1712007656131
        assert_eq!(
            base64::encode(serialized),
            "AAABjpubssMAAY0CU2yIdIK8NP9U5B0rplm/hbNBoKIK+ttYE9z7zyhtAAIKMIICBqADAgECAhID1hXG/Ytxz/LoiGtbmy9CYc8wDQYJKoZIhvcNAQELBQAwMjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxCzAJBgNVBAMTAlIzMB4XDTIzMTExNTEwMTkxMVoXDTI0MDIxMzEwMTkxMFowHTEbMBkGA1UEAxMScm9tZS5jdC5maWxpcHBvLmlvMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEy59AymL7lwJLDxroPax7puNNHpWlybmSvlvVQdollV0zi04LLrp3eI70twpjAh1ckkPVNu3MC4uVEJZrUc2UZKOCAQwwggEIMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUiKoO1vVHPpj2JUgPgkFGXfq0TjswHwYDVR0jBBgwFoAUFC6zF7dYVsuuUAlA5h+vnYsUwsYwVQYIKwYBBQUHAQEESTBHMCEGCCsGAQUFBzABhhVodHRwOi8vcjMuby5sZW5jci5vcmcwIgYIKwYBBQUHMAKGFmh0dHA6Ly9yMy5pLmxlbmNyLm9yZy8wHQYDVR0RBBYwFIIScm9tZS5jdC5maWxpcHBvLmlvMBMGA1UdIAQMMAowCAYGZ4EMAQIBAAgAAAUAAAAAAQADNzCCAzMwggIboAMCAQICEgPWFcb9i3HP8uiIa1ubL0JhzzANBgkqhkiG9w0BAQsFADAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5jcnlwdDELMAkGA1UEAxMCUjMwHhcNMjMxMTE1MTAxOTExWhcNMjQwMjEzMTAxOTEwWjAdMRswGQYDVQQDExJyb21lLmN0LmZpbGlwcG8uaW8wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATLn0DKYvuXAksPGug9rHum400elaXJuZK+W9VB2iWVXTOLTgsuund4jvS3CmMCHVySQ9U27cwLi5UQlmtRzZRko4IBITCCAR0wDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSIqg7W9Uc+mPYlSA+CQUZd+rROOzAfBgNVHSMEGDAWgBQULrMXt1hWy65QCUDmH6+dixTCxjBVBggrBgEFBQcBAQRJMEcwIQYIKwYBBQUHMAGGFWh0dHA6Ly9yMy5vLmxlbmNyLm9yZzAiBggrBgEFBQcwAoYWaHR0cDovL3IzLmkubGVuY3Iub3JnLzAdBgNVHREEFjAUghJyb21lLmN0LmZpbGlwcG8uaW8wEwYDVR0gBAwwCjAIBgZngQwBAgEwEwYKKwYBBAHWeQIEAwEB/wQCBQAwDQYJKoZIhvcNAQELBQADggEBAJOCut5mEbTqh9i6axnwQyF5zlxre8InHcgQ9mYebZKjAQdF7pXAIveCFHxDgUnyCM2eZU4fFrwAekcTBl2H/EMeHRwj9THKTL5DiTRM/XB1Y6AccfGrHQLFenfmr9zLCvN5/35zepaKMlKA89PQGTb5pUe+BwpqYC8nTDL/LoHYj40ZWC2isvMIgPh6V9q2+KFifZEg+3cbruvjaj4uKllbKKUCgTHGBIQn0DdurXJtl943m3MBN0xTcYSuUXEU1jDt4uQLWlGQ0+G1lExUxz/OuvMLwqSPDMnyJVXZVL9wTp8o76/86UgW/0n28hNMolASocZec9/iyJkzcMW3ObIAAAA="
        );
    }

    #[test]
    fn test_serialize_ct_extensions() {
        let entry = Entry {
            timestamp: 0,
            certs: Cert::X509 {
                cert: to_cert(TESTLEAF),
                chain: vec![to_cert(TESTINTERMEDIATE), to_cert(TESTROOT)],
            },
            raw_certs: vec![
                base64::decode(TESTLEAF).unwrap(),
                base64::decode(TESTINTERMEDIATE).unwrap(),
                base64::decode(TESTROOT).unwrap(),
            ],
            return_path: None,
            leaf_index: 1,
        };

        let serialized = serialize_ct_extensions(&entry);
        // Test value is from sunlight ctlog_test::testSubmit, with leaf index of 1.
        assert_eq!(base64::encode(serialized), "AAAFAAAAAAE=");
    }

    #[test]
    fn test_hash_leaf_cert() {
        let entry = Entry {
            timestamp: 1712084421303,
            certs: Cert::X509 {
                cert: to_cert(TESTLEAF),
                chain: vec![to_cert(TESTINTERMEDIATE), to_cert(TESTROOT)],
            },
            raw_certs: vec![
                base64::decode(TESTLEAF).unwrap(),
                base64::decode(TESTINTERMEDIATE).unwrap(),
                base64::decode(TESTROOT).unwrap(),
            ],
            return_path: None,
            leaf_index: 1,
        };

        let hash = hash_leaf(&entry);
        // Test value is from sunlight ctlog_test::testSubmit,
        // with leaf index of 1 and initial timestamp of 1712084421303
        assert_eq!(
            base64::encode(hash),
            "RWbMxqcmXbwOH/H9Iho7OAUPUL50JPEGtiv6tSex2Uk="
        );
    }

    #[test]
    fn test_hash_leaf_precert() {
        let entry = Entry {
            timestamp: 1712087251544,
            certs: Cert::Precert {
                cert: to_cert(TESTPRECERT).tbs_certificate,
                chain: vec![to_cert(TESTINTERMEDIATE), to_cert(TESTROOT)],
            },
            raw_certs: vec![
                base64::decode(TESTPRECERT).unwrap(),
                base64::decode(TESTINTERMEDIATE).unwrap(),
                base64::decode(TESTROOT).unwrap(),
            ],
            return_path: None,
            leaf_index: 1,
        };

        let hash = hash_leaf(&entry);
        // Test value is from sunlight ctlog_test::testSubmit,
        // with leaf index of 1 and initial timestamp of 1712087251544
        assert_eq!(
            base64::encode(hash),
            "qgngyYhaBNaku6nV3wVItek7dpdL+oQO/KlvQFxTxrw="
        );
    }

    #[test]
    fn test_sign_sct_cert() {
        // This signing key is generated by taking the below PKCS#8 key and
        // converting it to SEC1 using `openssl ec -in infile -out outfile`
        // -----BEGIN PRIVATE KEY-----
        // MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRQ1HwGWoTlh9bRwA
        // /7A4CTST3VYZnER+/uJsR2W1D6OhRANCAAR6sDo9eWsBf3XXsYpCUanCkcIMHqdx
        // 3AaVWE2X3cyzUexGeZePFmUD6k/KLT1BHsR4dQZKVgw5A1zlfnb29ZJV
        // -----END PRIVATE KEY-----

        const SIGNING_KEY: &str = indoc! {
            "-----BEGIN EC PRIVATE KEY-----
            MHcCAQEEIOOoLmwmoTOBVvmCzuqy5rtPQcuvE8+Ecaut9LkavFNtoAoGCCqGSM49
            AwEHoUQDQgAEjjtznKWgRjJ7YM8hMx/kJ/+y22wKT05qivyMw78S4q6vTjo+gQQs
            mQDpuuO2Ggdi4hH5HJe8eKfRCPllntk99A==
            -----END EC PRIVATE KEY-----"
        };

        let key = SecretKey::from_sec1_pem(SIGNING_KEY).unwrap();

        let entry = Entry {
            timestamp: 1712114097082,
            certs: Cert::X509 {
                cert: to_cert(TESTLEAF),
                chain: vec![to_cert(TESTINTERMEDIATE), to_cert(TESTROOT)],
            },
            raw_certs: vec![
                base64::decode(TESTLEAF).unwrap(),
                base64::decode(TESTINTERMEDIATE).unwrap(),
                base64::decode(TESTROOT).unwrap(),
            ],
            return_path: None,
            leaf_index: 1,
        };

        let signature = sign_sct(&entry, &key);
        // Test value is from sunlight ctlog_test::testSubmit,
        // with leaf index of 1 and initial timestamp of 1712114097082
        // and the signing key above
        assert_eq!(
            base64::encode(signature),
            "BAMARzBFAiA4xQJXwgo4ZBKuEvKbMyXWGFWgve1qxI0VGYD4Qli//gIhAMLs0a64OYLgcZLlajZaCVBwj6wcVBmi5bDNnjh5XNDg"
        );
    }

    #[test]
    fn test_sign_sct_precert() {
        // This signing key is generated by taking the below PKCS#8 key and
        // converting it to SEC1 using `openssl ec -in infile -out outfile`
        // -----BEGIN PRIVATE KEY-----
        // MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgk70OzVZihvI9v5Ns
        // 2acgG5nKPc2TbRktUxD0KbPnYYehRANCAAR158HUj8nrk0E9Wz/fEHzGEQJ/POOS
        // DEqczCH7JaGrlJhQVVu7QcVCay2OgbTQIyR6Rt7h+oEOagUKajJb4FMQ
        // -----END PRIVATE KEY-----

        const SIGNING_KEY: &str = indoc! {
            "-----BEGIN EC PRIVATE KEY-----
            MHcCAQEEIJO9Ds1WYobyPb+TbNmnIBuZyj3Nk20ZLVMQ9Cmz52GHoAoGCCqGSM49
            AwEHoUQDQgAEdefB1I/J65NBPVs/3xB8xhECfzzjkgxKnMwh+yWhq5SYUFVbu0HF
            QmstjoG00CMkekbe4fqBDmoFCmoyW+BTEA==
            -----END EC PRIVATE KEY-----"
        };

        let key = SecretKey::from_sec1_pem(SIGNING_KEY).unwrap();

        let entry = Entry {
            timestamp: 1712115722936,
            certs: Cert::Precert {
                cert: to_cert(TESTPRECERT).tbs_certificate,
                chain: vec![to_cert(TESTINTERMEDIATE), to_cert(TESTROOT)],
            },
            raw_certs: vec![
                base64::decode(TESTPRECERT).unwrap(),
                base64::decode(TESTINTERMEDIATE).unwrap(),
                base64::decode(TESTROOT).unwrap(),
            ],
            return_path: None,
            leaf_index: 1,
        };

        let signature = sign_sct(&entry, &key);
        // Test value is from sunlight ctlog_test::testSubmit,
        // with leaf index of 1 and initial timestamp of 1712115722936
        // and the signing key above
        assert_eq!(
            base64::encode(signature),
            "BAMARzBFAiEAryWhMFgOZPk6c/Y+CGxyV2r5vhyb0Y4iybncS+teYRoCIHcUeYYh4DQlqOENxTHuUQMM6gmg/O/yFo3RrysLCfN1"
        );
    }

    #[test]
    fn test_sign_checkpoint() {
        // This signing key is generated by taking the below PKCS#8 key and
        // converting it to SEC1 using `openssl ec -in infile -out outfile`
        // -----BEGIN

        const SIGNING_KEY: &str = indoc! {
            "-----BEGIN EC PRIVATE KEY
            "
        };

        let key = SecretKey::from_sec1_pem(SIGNING_KEY).unwrap();

        let timestamp = 0;

        let checkpoint = sign_checkpoint(timestamp, &key);

        assert_eq!(
            checkpoint,
            indoc! {
            "example.com/TestLog
            2
            2qLlcDGIesan3UzgOjFntFxg2MhHYRvIRgAnri683g8=
            
            — example.com/TestLog C1CKowAAAY7TjS6oBAMARzBFAiBNkcsJytN9d/HjfPyUEACTs6+FDGKzmavn+vSvno94JQIhAL5UsSUNYmcuSehQyMi3/CxnOEP1+6OXB3G89zvNtRJb"
            }
        )
    }
}
