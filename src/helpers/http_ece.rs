//! Payload encryption algorithm

use crate::helpers::ece::encrypt;
use base64::engine::general_purpose;
use base64::Engine;

use crate::helpers::error::WebPushError;
use crate::helpers::message::WebPushPayload;
use crate::helpers::vapid::VapidSignature;

/// Content encoding profiles.
#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub enum ContentEncoding {
    //Make sure this enum remains exhaustive as that allows for easier migrations to new versions.
    #[default]
    Aes128Gcm,
    /// Note: this is an older version of ECE, and should not be used unless you know for sure it is required. In all other cases, use aes128gcm.
    AesGcm,
}

impl ContentEncoding {
    /// Gets the associated string for this content encoding, as would be used in the content-encoding header.
    pub fn to_str(&self) -> &'static str {
        match &self {
            ContentEncoding::Aes128Gcm => "aes128gcm",
            ContentEncoding::AesGcm => "aesgcm",
        }
    }
}

/// Struct for handling payload encryption.
pub struct HttpEce<'a> {
    peer_public_key: &'a [u8],
    peer_secret: &'a [u8],
    encoding: ContentEncoding,
    vapid_signature: Option<VapidSignature>,
}

impl<'a> HttpEce<'a> {
    /// Create a new encryptor.
    ///
    /// `peer_public_key` is the `p256dh` and `peer_secret` the `auth` from
    /// browser subscription info.
    pub fn new(
        encoding: ContentEncoding,
        peer_public_key: &'a [u8],
        peer_secret: &'a [u8],
        vapid_signature: Option<VapidSignature>,
    ) -> HttpEce<'a> {
        HttpEce {
            peer_public_key,
            peer_secret,
            encoding,
            vapid_signature,
        }
    }

    /// Encrypts a payload. The maximum length for the payload is 3800
    /// characters, which is the largest that works with Google's and Mozilla's
    /// push servers.
    pub fn encrypt(&self, content: &'a [u8]) -> Result<WebPushPayload, WebPushError> {
        if content.len() > 3052 {
            return Err(WebPushError::PayloadTooLarge);
        }

        let salt = rand::random::<[u8; 16]>();

        //Add more encoding standards to this match as they are created.
        match self.encoding {
            ContentEncoding::Aes128Gcm => {
                let result = encrypt(
                    self.peer_secret,
                    salt,
                    self.peer_public_key,
                    vec![content.to_vec()].into_iter(),
                    230,
                    true,
                );

                let mut headers = vec![];

                self.add_vapid_headers(&mut headers);

                match result {
                    Ok(data) => Ok(WebPushPayload {
                        content: data,
                        crypto_headers: headers,
                        content_encoding: self.encoding,
                    }),
                    _ => Err(WebPushError::InvalidCryptoKeys),
                }
            }
            ContentEncoding::AesGcm => {
                let result = {
                    let mut headers = vec![
                        (
                            "Encryption",
                            format!("salt={}", general_purpose::URL_SAFE.encode(&salt)),
                        ),
                        (
                            "Crypto-Key",
                            format!(
                                "dh={}",
                                general_purpose::URL_SAFE.encode(self.peer_public_key)
                            ),
                        ),
                    ];

                    let result = encrypt(
                        self.peer_secret,
                        salt,
                        self.peer_public_key,
                        vec![content.to_vec()].into_iter(),
                        230,
                        true,
                    );

                    self.add_vapid_headers(&mut headers);

                    result.map(|encrypted| WebPushPayload {
                        content: encrypted,
                        crypto_headers: headers,
                        content_encoding: self.encoding,
                    })
                };
                result.map_err(|_| WebPushError::InvalidCryptoKeys)
            }
        }
    }

    /// Adds VAPID authorisation header to headers, if VAPID is being used.
    fn add_vapid_headers(&self, headers: &mut Vec<(&str, String)>) {
        //VAPID uses a special Authorisation header, which contains a ecdhsa key and a jwt.
        if let Some(signature) = &self.vapid_signature {
            headers.push((
                "Authorization",
                format!(
                    "vapid t={}, k={}",
                    signature.auth_t,
                    general_purpose::URL_SAFE.encode(&signature.auth_k)
                ),
            ));
        }
    }
}

#[cfg(test)]
mod tests {

    use base64::engine::general_purpose;
    use base64::{self, engine, Engine};
    use regex::Regex;

    use crate::helpers::ece::decrypt;
    use crate::helpers::error::WebPushError;
    use crate::helpers::http_ece::{ContentEncoding, HttpEce};
    use crate::helpers::VapidSignature;
    use crate::helpers::WebPushPayload;
    use p256::{PublicKey, SecretKey};
    use rand::rngs::OsRng;

    pub(crate) struct KeyComponents {
        pub secret_key: SecretKey,
        pub public_key: Vec<u8>,
        pub auth: Vec<u8>,
    }

    fn generate_test_keypair() -> KeyComponents {
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = PublicKey::from_secret_scalar(&secret_key.to_nonzero_scalar());
        let public_bytes = public_key.to_sec1_bytes().to_vec();
        let auth = rand::random::<[u8; 16]>().to_vec();

        KeyComponents {
            secret_key,
            public_key: public_bytes,
            auth,
        }
    }

    #[test]
    fn test_payload_too_big() {
        let p256dh = engine::general_purpose::URL_SAFE_NO_PAD.decode(
            "BLMaF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8"
        )
        .unwrap();
        let auth = engine::general_purpose::URL_SAFE_NO_PAD
            .decode("xS03Fj5ErfTNH_l9WHE9Ig")
            .unwrap();
        let http_ece = HttpEce::new(ContentEncoding::Aes128Gcm, &p256dh, &auth, None);
        //This content is one above limit.
        let content = [0u8; 3801];

        assert!(matches!(
            http_ece.encrypt(&content),
            Err(WebPushError::PayloadTooLarge)
        ));
    }

    /// Tests that the content encryption is properly reversible while using aes128gcm.
    #[test]
    fn test_payload_encrypts_128() {
        let test_keys = generate_test_keypair();

        let http_ece = HttpEce::new(
            ContentEncoding::Aes128Gcm,
            &test_keys.public_key,
            &test_keys.auth,
            None,
        );
        let plaintext = "Hello world!";
        let ciphertext = http_ece.encrypt(plaintext.as_bytes()).unwrap();

        assert_ne!(plaintext.as_bytes(), ciphertext.content);

        let decrypted = decrypt::<&[u8]>(
            &test_keys.auth,
            ciphertext.content,
            Some(plaintext.as_bytes().len()),
        )
        .unwrap();
        assert_eq!(String::from_utf8(decrypted).unwrap(), plaintext)
    }

    /// Tests that the content encryption is properly reversible while using aesgcm.
    #[test]
    fn test_payload_encrypts() {
        let test_keys = generate_test_keypair();
        let http_ece = HttpEce::new(
            ContentEncoding::AesGcm,
            &test_keys.public_key,
            &test_keys.auth,
            None,
        );
        let plaintext = "Hello world!";
        let ciphertext = http_ece.encrypt(plaintext.as_bytes()).unwrap();

        assert_ne!(plaintext.as_bytes(), ciphertext.content);

        let decrypted = decrypt::<&[u8]>(
            &test_keys.auth,
            ciphertext.content,
            Some(plaintext.as_bytes().len()),
        )
        .unwrap();
        assert_eq!(String::from_utf8(decrypted).unwrap(), plaintext);
    }

    fn setup_payload(
        vapid_signature: Option<VapidSignature>,
        encoding: ContentEncoding,
    ) -> WebPushPayload {
        let p256dh = general_purpose::URL_SAFE_NO_PAD.decode(
            "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
        )
        .unwrap();
        let auth = general_purpose::URL_SAFE_NO_PAD
            .decode("xS03Fi5ErfTNH_l9WHE9Ig")
            .unwrap();

        let http_ece = HttpEce::new(encoding, &p256dh, &auth, vapid_signature);
        let content = "Hello, world!".as_bytes();

        http_ece.encrypt(content).unwrap()
    }

    #[test]
    fn test_aes128gcm_headers_no_vapid() {
        let wp_payload = setup_payload(None, ContentEncoding::Aes128Gcm);
        assert_eq!(wp_payload.crypto_headers.len(), 0);
    }

    #[test]
    fn test_aesgcm_headers_no_vapid() {
        let wp_payload = setup_payload(None, ContentEncoding::AesGcm);
        assert_eq!(wp_payload.crypto_headers.len(), 2);
    }

    #[test]
    fn test_aes128gcm_headers_vapid() {
        let auth_re = Regex::new(r"vapid t=(?P<sig_t>[^,]*), k=(?P<sig_k>[^,]*)").unwrap();
        let vapid_signature = VapidSignature {
            auth_t: String::from("foo"),
            auth_k: String::from("bar").into_bytes(),
        };
        let wp_payload = setup_payload(Some(vapid_signature), ContentEncoding::Aes128Gcm);
        assert_eq!(wp_payload.crypto_headers.len(), 1);
        let auth = wp_payload.crypto_headers[0].clone();
        assert_eq!(auth.0, "Authorization");
        assert!(auth_re.captures(&auth.1).is_some());
    }

    #[test]
    fn test_aesgcm_headers_vapid() {
        let auth_re = Regex::new(r"vapid t=(?P<sig_t>[^,]*), k=(?P<sig_k>[^,]*)").unwrap();
        let vapid_signature = VapidSignature {
            auth_t: String::from("foo"),
            auth_k: String::from("bar").into_bytes(),
        };
        let wp_payload = setup_payload(Some(vapid_signature), ContentEncoding::AesGcm);
        // Should have Authorization, Crypto-key, and Encryption
        assert_eq!(wp_payload.crypto_headers.len(), 3);
        let auth = wp_payload.crypto_headers[2].clone();
        assert_eq!(auth.0, "Authorization");
        assert!(auth_re.captures(&auth.1).is_some());
    }
}
