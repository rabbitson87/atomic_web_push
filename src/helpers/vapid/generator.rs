use base64::{engine, Engine};
use base64ct::LineEnding;
use p256::{
    ecdsa::{SigningKey, VerifyingKey},
    SecretKey,
};

use crate::{atomic_jwt::prelude::ES256KeyPair, WebPushError};

use super::key::VapidKey;

pub struct VapidKeyGenerator {
    secret_key: SecretKey,
    verifying_key: VerifyingKey,
}

impl VapidKeyGenerator {
    pub fn new() -> Result<Self, WebPushError> {
        // create a new VapidKeyGenerator
        let secret_key = SecretKey::random(&mut rand::thread_rng());
        // create a new SigningKey from the secret key
        let signing_key = SigningKey::from(secret_key.clone());
        let verifying_key = VerifyingKey::from(&signing_key);

        Ok(Self {
            secret_key,
            verifying_key,
        })
    }

    pub fn secret_key_base64(&self) -> String {
        engine::general_purpose::URL_SAFE_NO_PAD.encode(self.secret_key.to_bytes())
    }

    pub fn public_key_uncompressed(&self) -> Vec<u8> {
        self.verifying_key
            .to_encoded_point(false)
            .to_bytes()
            .to_vec()
    }

    pub fn public_key_base64(&self) -> String {
        engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.public_key_uncompressed())
    }

    pub fn secret_key_bytes(&self) -> Vec<u8> {
        self.secret_key.to_bytes().to_vec()
    }

    pub fn secret_key_to_pem(&self) -> Result<String, WebPushError> {
        let sec1_bytes = self
            .secret_key
            .to_sec1_pem(LineEnding::LF)
            .map_err(|_| WebPushError::InvalidSecretKey)?;
        Ok(sec1_bytes.to_string())
    }

    pub fn from_pem(pem_str: &str) -> Result<Self, WebPushError> {
        let secret_key =
            SecretKey::from_sec1_pem(pem_str).map_err(|_| WebPushError::InvalidSecretKey)?;
        let signing_key = SigningKey::from(secret_key.clone());
        let verifying_key = VerifyingKey::from(&signing_key);

        Ok(Self {
            secret_key,
            verifying_key,
        })
    }

    pub fn from_base64(encoded: &str) -> Result<Self, WebPushError> {
        let decoded = engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| WebPushError::InvalidSecretKey)?;

        let secret_key =
            SecretKey::from_slice(&decoded).map_err(|_| WebPushError::InvalidSecretKey)?;

        let signing_key = SigningKey::from(secret_key.clone());
        let verifying_key = VerifyingKey::from(&signing_key);

        Ok(Self {
            secret_key,
            verifying_key,
        })
    }

    pub fn to_es256_keypair(&self) -> ES256KeyPair {
        ES256KeyPair::from_bytes(&self.secret_key_bytes()).expect("Valid P-256 key")
    }

    pub fn to_vapid_key(&self) -> VapidKey {
        VapidKey::new(self.to_es256_keypair())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    #[test]
    fn test_generate_new_vapid_key() {
        let generator = VapidKeyGenerator::new().expect("Failed to create generator");

        // Check that public key is in uncompressed format (65 bytes)
        let public_key = generator.public_key_uncompressed();
        assert_eq!(public_key.len(), 65);
        assert_eq!(public_key[0], 4); // Uncompressed point format indicator

        // Check that secret key is correct length (32 bytes)
        let secret_key = generator.secret_key_bytes();
        assert_eq!(secret_key.len(), 32);
    }

    #[test]
    fn test_base64_encoding_decoding() {
        let generator = VapidKeyGenerator::new().expect("Failed to create generator");

        let secret_base64 = generator.secret_key_base64();
        let public_base64 = generator.public_key_base64();

        // Test secret key base64 decoding
        let decoded_secret = URL_SAFE_NO_PAD
            .decode(&secret_base64)
            .expect("Failed to decode secret");
        assert_eq!(decoded_secret, generator.secret_key_bytes());

        // Test public key base64 decoding
        let decoded_public = URL_SAFE_NO_PAD
            .decode(&public_base64)
            .expect("Failed to decode public");
        assert_eq!(decoded_public, generator.public_key_uncompressed());
    }

    #[test]
    fn test_from_base64() {
        let original = VapidKeyGenerator::new().expect("Failed to create generator");
        let secret_base64 = original.secret_key_base64();

        // Recreate generator from base64 secret
        let restored =
            VapidKeyGenerator::from_base64(&secret_base64).expect("Failed to restore from base64");

        // Check that both generators produce the same keys
        assert_eq!(original.secret_key_bytes(), restored.secret_key_bytes());
        assert_eq!(
            original.public_key_uncompressed(),
            restored.public_key_uncompressed()
        );
        assert_eq!(original.public_key_base64(), restored.public_key_base64());
    }

    #[test]
    fn test_invalid_base64() {
        // Test with invalid base64 string
        let result = VapidKeyGenerator::from_base64("invalid-base64!");
        assert!(result.is_err());

        // Test with valid base64 but invalid key length
        let result = VapidKeyGenerator::from_base64("aGVsbG8="); // "hello" in base64
        assert!(result.is_err());
    }

    #[test]
    fn test_pem_encoding_decoding() {
        let original = VapidKeyGenerator::new().expect("Failed to create generator");

        // Convert to PEM
        let pem = original.secret_key_to_pem().expect("Failed to create PEM");

        // Check PEM format
        assert!(pem.contains("-----BEGIN EC PRIVATE KEY-----"));
        assert!(pem.contains("-----END EC PRIVATE KEY-----"));

        // Restore from PEM
        let restored = VapidKeyGenerator::from_pem(&pem).expect("Failed to restore from PEM");

        // Verify keys match
        assert_eq!(original.secret_key_bytes(), restored.secret_key_bytes());
        assert_eq!(
            original.public_key_uncompressed(),
            restored.public_key_uncompressed()
        );
    }

    #[test]
    fn test_vapid_key_conversion() {
        let generator = VapidKeyGenerator::new().expect("Failed to create generator");

        // Convert to VapidKey
        let vapid_key = generator.to_vapid_key();

        // Check that public key matches
        assert_eq!(generator.public_key_uncompressed(), vapid_key.public_key());
    }

    #[test]
    fn test_known_test_vector() {
        // Use a known test vector for testing
        // Example: Use the test keys from the web-push library
        let known_private_base64 = "IQ9Ur0ykXoHS9gzfYX0aBjy9lvdrjx_PFUXmie9YRcY";
        let known_public_base64 = "BMjQIp55pdbU8pfCBKyXcZjlmER_mXt5LqNrN1hrXbdBS5EnhIbMu3Au-RV53iIpztzNXkGI56BFB1udQ8Bq_H4";

        let generator = VapidKeyGenerator::from_base64(known_private_base64)
            .expect("Failed to create from known private key");

        assert_eq!(generator.public_key_base64(), known_public_base64);
    }

    #[test]
    fn test_generate() {
        // Generate a new key pair and print the base64 values
        let generator = VapidKeyGenerator::new().expect("Failed to create generator");

        let secret_base64 = generator.secret_key_base64();
        let public_base64 = generator.public_key_base64();
        println!("Secret key: {}", secret_base64);
        println!("Public key: {}", public_base64);
    }
}
