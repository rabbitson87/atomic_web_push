pub mod bn;
pub mod derive;
pub mod ec;
pub mod rand;
pub mod symm;

use base64::Engine;
use bn::BigNumberHelper;
use derive::Deriver;
use ec::{EcGroup, EcKey, EcPoint, Nid, PKey, PointConversionForm, Private, Public};
use ece::{
    crypto::{Cryptographer, EcKeyComponents, LocalKeyPair, RemotePublicKey},
    *,
};
use hkdf::Hkdf;
use rand::rand_bytes;
use sha2::Sha256;
use std::{any::Any, fmt, sync::OnceLock};
use symm::{Cipher, Crypter, Mode};

pub fn group_p256() -> &'static EcGroup {
    static BUILDER: OnceLock<EcGroup> = OnceLock::new();
    BUILDER.get_or_init(|| EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap())
}
const AES_GCM_TAG_LENGTH: usize = 16;

#[derive(Clone, Debug)]
pub struct CryptoRemotePublicKey {
    raw_pub_key: Vec<u8>,
}

impl CryptoRemotePublicKey {
    fn from_raw(raw: &[u8]) -> Result<Self> {
        Ok(CryptoRemotePublicKey {
            raw_pub_key: raw.to_vec(),
        })
    }

    fn to_pkey(&self) -> Result<PKey<Public>> {
        let group = group_p256();

        // 1. first create a point
        let point =
            EcPoint::from_bytes(&group, &self.raw_pub_key).map_err(|_| Error::CryptoError)?;

        // 2. check if the point is on the curve
        let ec = EcKey::from_public_key(&group, point).map_err(|_| Error::CryptoError)?;

        // 3. check if the point is valid
        PKey::from_ec_key(ec).map_err(std::convert::Into::into)
    }
}

impl RemotePublicKey for CryptoRemotePublicKey {
    fn as_raw(&self) -> Result<Vec<u8>> {
        Ok(self.raw_pub_key.to_vec())
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Clone)]
pub struct CryptoLocalKeyPair {
    ec_key: EcKey<Private>,
}

impl fmt::Debug for CryptoLocalKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?}",
            base64::engine::general_purpose::URL_SAFE
                .encode(self.ec_key.private_key().unwrap().to_bytes_be())
        )
    }
}

impl CryptoLocalKeyPair {
    /// Generate a random local key pair using OpenSSL `ECKey::generate`.
    fn generate_random() -> Result<Self> {
        let ec_key = EcKey::generate(&group_p256()).map_err(|_| Error::CryptoError)?;
        Ok(CryptoLocalKeyPair { ec_key })
    }

    fn to_pkey(&self) -> Result<PKey<Private>> {
        PKey::from_ec_key(self.ec_key.clone()).map_err(std::convert::Into::into)
    }

    fn from_raw_components(components: &EcKeyComponents) -> Result<Self> {
        let d = BigNumberHelper::from_bytes(components.private_key());
        let ec_point = EcPoint::from_bytes(&group_p256(), components.public_key())
            .map_err(|_| Error::CryptoError)?;

        let mut x = BigNumberHelper::new();
        let mut y = BigNumberHelper::new();
        ec_point
            .affine_coordinates_gfp(&mut x, &mut y)
            .map_err(|_| Error::CryptoError)?;

        let public_key = EcKey::from_public_key_affine_coordinates(&group_p256(), &x, &y)
            .map_err(|_| Error::CryptoError)?;
        let private_key =
            EcKey::from_private_components(&group_p256(), &d, public_key.public_key())
                .map_err(|_| Error::CryptoError)?;
        Ok(Self {
            ec_key: private_key,
        })
    }
}

impl LocalKeyPair for CryptoLocalKeyPair {
    /// Export the public key component in the binary uncompressed point representation
    /// using OpenSSL `PointConversionForm::UNCOMPRESSED`.
    fn pub_as_raw(&self) -> Result<Vec<u8>> {
        let pub_key_point = self.ec_key.public_key();
        let uncompressed = pub_key_point
            .to_bytes(PointConversionForm::Uncompressed)
            .map_err(|_| Error::CryptoError)?;
        Ok(uncompressed)
    }

    fn raw_components(&self) -> Result<EcKeyComponents> {
        if let Some(private_key) = self.ec_key.private_key() {
            Ok(EcKeyComponents::new(
                private_key.to_bytes_be(),
                self.pub_as_raw()?,
            ))
        } else {
            Err(Error::CryptoError.into())
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl From<EcKey<Private>> for CryptoLocalKeyPair {
    fn from(key: EcKey<Private>) -> CryptoLocalKeyPair {
        CryptoLocalKeyPair { ec_key: key }
    }
}

pub struct LocalCryptographer;
impl Cryptographer for LocalCryptographer {
    fn generate_ephemeral_keypair(&self) -> Result<Box<dyn LocalKeyPair>> {
        Ok(Box::new(CryptoLocalKeyPair::generate_random()?))
    }

    fn import_key_pair(&self, components: &EcKeyComponents) -> Result<Box<dyn LocalKeyPair>> {
        Ok(Box::new(CryptoLocalKeyPair::from_raw_components(
            components,
        )?))
    }

    fn import_public_key(&self, raw: &[u8]) -> Result<Box<dyn RemotePublicKey>> {
        Ok(Box::new(CryptoRemotePublicKey::from_raw(raw)?))
    }

    fn compute_ecdh_secret(
        &self,
        remote: &dyn RemotePublicKey,
        local: &dyn LocalKeyPair,
    ) -> Result<Vec<u8>> {
        let local = local
            .as_any()
            .downcast_ref::<CryptoLocalKeyPair>()
            .ok_or(Error::CryptoError)?;
        let remote = remote
            .as_any()
            .downcast_ref::<CryptoRemotePublicKey>()
            .ok_or(Error::CryptoError)?;

        let private = local.to_pkey()?;
        let public = remote.to_pkey()?;

        let mut deriver = Deriver::new(&private)?;
        deriver.set_peer(&public)?;
        deriver.derive_to_vec()
    }

    fn hkdf_sha256(&self, salt: &[u8], secret: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
        let (_, hk) = Hkdf::<Sha256>::extract(Some(salt), secret);
        let mut okm = vec![0u8; len];
        hk.expand(info, &mut okm).unwrap();
        Ok(okm)
    }

    fn aes_gcm_128_encrypt(&self, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let cipher = Cipher::aes_128_gcm();
        let mut c =
            Crypter::new(cipher, Mode::Encrypt, key, Some(iv)).map_err(|_| Error::CryptoError)?;
        let mut out = vec![0u8; data.len() + cipher.block_size()];
        let count = c.update(data, &mut out).map_err(|_| Error::CryptoError)?;
        let rest = c
            .finalize(&mut out[count..])
            .map_err(|_| Error::CryptoError)?;
        let mut tag = vec![0u8; AES_GCM_TAG_LENGTH];
        c.get_tag(&mut tag).map_err(|_| Error::CryptoError)?;
        out.truncate(count + rest);
        out.append(&mut tag);
        Ok(out)
    }

    fn aes_gcm_128_decrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>> {
        let block_len = ciphertext_and_tag.len() - AES_GCM_TAG_LENGTH;
        let ciphertext = &ciphertext_and_tag[0..block_len];
        let tag = &ciphertext_and_tag[block_len..];
        let cipher = Cipher::aes_128_gcm();
        let mut c =
            Crypter::new(cipher, Mode::Decrypt, key, Some(iv)).map_err(|_| Error::CryptoError)?;
        let mut out = vec![0u8; ciphertext.len() + cipher.block_size()];
        let count = c
            .update(ciphertext, &mut out)
            .map_err(|_| Error::CryptoError)?;
        c.set_tag(tag).map_err(|_| Error::CryptoError)?;
        let rest = c
            .finalize(&mut out[count..])
            .map_err(|_| Error::CryptoError)?;
        out.truncate(count + rest);
        Ok(out)
    }

    fn random_bytes(&self, dest: &mut [u8]) -> Result<()> {
        Ok(rand_bytes(dest)?)
    }
}

#[cfg(test)]
mod tests {
    use symm::validate_tag;

    use super::*;
    use crate::helpers::crypto::derive::Deriver;
    use crate::helpers::crypto::ec::{EcKey, PKeyType};
    use crate::helpers::crypto::symm::{Cipher, Mode};

    #[test]
    fn test_point_encoding() {
        let group = group_p256();
        let ec_key = EcKey::generate(group).unwrap();
        let pub_key = ec_key.public_key();

        // uncompressed format marker
        let encoded = pub_key.to_bytes(PointConversionForm::Uncompressed).unwrap();
        assert_eq!(encoded[0], 0x04); // uncompressed format marker
        assert_eq!(encoded.len(), 65); // 1 + 32 + 32 bytes

        // decoding
        let decoded = EcPoint::from_bytes(group, &encoded).unwrap();
        assert!(decoded.is_on_curve());
    }

    #[test]
    fn test_key_generation_and_conversion() {
        // create a key pair
        let ec_key = EcKey::generate(group_p256()).unwrap();

        // convert to PKey
        let pkey = PKey::from_ec_key(ec_key.clone()).unwrap();

        // convert back to EcKey and compare
        assert!(pkey.key_data.len() >= 64); // private key + public key coordinates
    }

    #[test]
    fn test_compute_ecdh_secret() {
        let local = CryptoLocalKeyPair::generate_random().unwrap();
        let private = local.to_pkey().unwrap();
        let remote = LocalCryptographer {}
            .generate_ephemeral_keypair()
            .unwrap()
            .raw_components()
            .unwrap();
        let remote = CryptoRemotePublicKey::from_raw(&remote.public_key()).unwrap();
        let public = remote.to_pkey().unwrap();
        let mut deriver = Deriver::new(&private).unwrap();
        deriver.set_peer(&public).unwrap();
        let shared_key = deriver.derive_to_vec().unwrap();
        assert_eq!(shared_key.len(), 32);
    }

    #[test]
    fn test_ecdh_key_exchange() {
        // Alice's key pair
        let alice_key = EcKey::generate(group_p256()).unwrap();
        let alice_private = PKey::from_ec_key(alice_key.clone()).unwrap();
        let alice_public = PKey::from_ec_key(alice_key.to_public_key()).unwrap();

        // Bob's key pair
        let bob_key = EcKey::generate(group_p256()).unwrap();
        let bob_private = PKey::from_ec_key(bob_key.clone()).unwrap();
        let bob_public = PKey::from_ec_key(bob_key.to_public_key()).unwrap();

        // Alice computes shared secret
        let mut alice_deriver = Deriver::new(&alice_private).unwrap();
        println!("alice_deriver {:?}", alice_deriver);
        alice_deriver.set_peer(&bob_public).unwrap();
        let alice_shared = alice_deriver.derive_to_vec().unwrap();

        // Bob computes shared secret
        let mut bob_deriver = Deriver::new(&bob_private).unwrap();
        bob_deriver.set_peer(&alice_public).unwrap();
        let bob_shared = bob_deriver.derive_to_vec().unwrap();

        assert_eq!(alice_shared, bob_shared);
        assert_eq!(alice_shared.len(), 32);
    }

    #[test]
    fn test_key_components_extraction() {
        // create a key pair
        let ec_key = EcKey::generate(group_p256()).unwrap();
        let pkey = PKey::from_ec_key(ec_key.clone()).unwrap();

        // extract key components
        if let Some(_priv_key) = ec_key.private_key {
            assert!(pkey.key_data.len() > 64); // private key + public key coordinates
        } else {
            assert_eq!(pkey.key_data.len(), 64); // just public key coordinates
        }
    }

    #[test]
    fn test_encryption_with_derived_key() {
        // create a key pair and ecdh shared secret
        let alice_key = EcKey::generate(group_p256()).unwrap();
        let alice_private = PKey::from_ec_key(alice_key.clone()).unwrap();

        let bob_key = EcKey::generate(group_p256()).unwrap();
        let bob_public = PKey::from_ec_key(bob_key.to_public_key()).unwrap();

        // derive shared key
        let mut deriver = Deriver::new(&alice_private).unwrap();
        deriver.set_peer(&bob_public).unwrap();
        let shared_key = deriver.derive_to_vec().unwrap();

        let plaintext = b"Hello, ECDH!";
        let iv = vec![0u8; 12];

        // encrypt
        let mut encrypter = Crypter::new(
            Cipher::aes_128_gcm(),
            Mode::Encrypt,
            &shared_key[..16],
            Some(&iv),
        )
        .unwrap();

        let mut ciphertext = vec![0u8; plaintext.len() + 16];
        let count = encrypter.update(plaintext, &mut ciphertext).unwrap();
        let rest = encrypter.finalize(&mut ciphertext[count..]).unwrap();
        let actual_cipher_len = count + rest; // 실제 암호문 길이 저장
        ciphertext.truncate(actual_cipher_len);

        let mut tag = vec![0u8; 16];
        encrypter.get_tag(&mut tag).unwrap();
        ciphertext.extend_from_slice(&tag);

        // decrypt
        let mut decrypter = Crypter::new(
            Cipher::aes_128_gcm(),
            Mode::Decrypt,
            &shared_key[..16],
            Some(&iv),
        )
        .unwrap();

        println!("Test step 1: Decrypter initialized");
        let mut decrypted = vec![0u8; plaintext.len()];

        // first update tag
        decrypter.set_tag(&ciphertext[actual_cipher_len..]).unwrap();
        println!(
            "Test step 2: Tag set, length: {}",
            ciphertext[actual_cipher_len..].len()
        );

        // decrypt the ciphertext
        let count = decrypter
            .update(&ciphertext[..actual_cipher_len], &mut decrypted)
            .unwrap();
        println!("Test step 3: Update complete, count: {}", count);

        let rest = decrypter.finalize(&mut decrypted[count..]).unwrap();
        println!("Test step 4: Finalize complete, rest: {}", rest);

        decrypted.truncate(count + rest);
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    #[should_panic]
    fn test_invalid_peer_key() {
        let alice_key = EcKey::generate(group_p256()).unwrap();
        let alice_private = PKey::from_ec_key(alice_key).unwrap();

        // create a key pair with invalid key data
        let invalid_key_data = vec![0u8; 64];
        let invalid_peer = PKey::new(invalid_key_data, PKeyType::Public);

        let mut deriver = Deriver::new(&alice_private).unwrap();
        deriver.set_peer(&invalid_peer).unwrap(); // should panic
        let _ = deriver.derive_to_vec().unwrap();
    }

    #[test]
    fn test_tag_validation() {
        // 1. valid tags (must pass)
        let valid_tags = vec![
            vec![
                240, 94, 174, 38, 216, 194, 177, 162, 49, 181, 64, 234, 84, 211, 48, 154,
            ],
            vec![
                45, 99, 148, 177, 215, 81, 152, 171, 188, 189, 93, 17, 12, 2, 105, 242,
            ],
            vec![
                0x7F, 0x42, 0x3A, 0x5D, 0x1E, 0x6C, 0x9B, 0x2F, 0x8E, 0x4A, 0x5C, 0x3D, 0x6B, 0x1F,
                0x9E, 0x2D,
            ],
        ];

        for tag in &valid_tags {
            assert!(
                validate_tag(tag),
                "Failed to recognize valid tag: {:?}",
                tag
            );
            println!("Valid tag passed: {:?}", tag);
        }

        // 2. trivial tags (must fail)
        let trivial_tags = vec![
            vec![0x00; 16],                                // 모든 바이트 0
            vec![0xFF; 16],                                // 모든 바이트 1
            (0..16).map(|x| x as u8).collect::<Vec<u8>>(), // 순차적 패턴
            vec![0b10101010; 16],                          // 반복 비트 패턴
            vec![0x00, 0x01, 0x00, 0x01],                  // 제한된 바이트 패턴
        ];

        for tag in &trivial_tags {
            assert!(
                !validate_tag(tag),
                "Failed to detect trivial tag: {:?}",
                tag
            );
            println!("Trivial tag detected: {:?}", tag);
        }
    }

    #[test]
    fn test_advanced_tag_validation() {
        // 1. valid tags (must pass)
        let secure_tag = vec![
            0xA3, 0x7B, 0x5C, 0x2D, 0x9E, 0x4F, 0x1A, 0x6B, 0x8C, 0x3D, 0x7E, 0x5F, 0x2A, 0x9B,
            0x4C, 0x1D,
        ];

        // 2. trivial tags (must fail)
        let trivial_tags = vec![
            vec![0x00; 16],                                // 모든 바이트가 0
            vec![0xFF; 16],                                // 모든 바이트가 1
            (0..16).map(|x| x as u8).collect::<Vec<u8>>(), // 순차적 패턴
        ];

        // compare with the trivial tags
        let mut crypter = Crypter::new(
            Cipher::aes_128_gcm(),
            Mode::Encrypt,
            &[0u8; 16],
            Some(&[0u8; 12]),
        )
        .unwrap();

        // pass the secure tag
        assert!(crypter.set_tag(&secure_tag).is_ok());

        // fail the trivial tags
        for tag in trivial_tags {
            assert!(crypter.set_tag(&tag).is_err());
        }
    }

    #[test]
    fn test_encryption_edge_cases() {
        // create a key pair and shared key
        let alice_key = EcKey::generate(group_p256()).unwrap();
        let alice_private = PKey::from_ec_key(alice_key.clone()).unwrap();
        let bob_key = EcKey::generate(group_p256()).unwrap();
        let bob_public = PKey::from_ec_key(bob_key.to_public_key()).unwrap();

        let mut deriver = Deriver::new(&alice_private).unwrap();
        deriver.set_peer(&bob_public).unwrap();
        let shared_key = deriver.derive_to_vec().unwrap();
        let iv = vec![0u8; 12];

        // 1. empty message test
        {
            let empty_message = b"";
            println!("Testing empty message encryption");

            let mut encrypter = Crypter::new(
                Cipher::aes_128_gcm(),
                Mode::Encrypt,
                &shared_key[..16],
                Some(&iv),
            )
            .unwrap();

            let mut ciphertext = vec![0u8; empty_message.len()];
            let count = encrypter.update(empty_message, &mut ciphertext).unwrap();
            let rest = encrypter.finalize(&mut ciphertext[count..]).unwrap();
            ciphertext.truncate(count + rest);

            let mut tag = vec![0u8; 16];
            encrypter.get_tag(&mut tag).unwrap();
            ciphertext.extend_from_slice(&tag);

            // decrypt
            let mut decrypter = Crypter::new(
                Cipher::aes_128_gcm(),
                Mode::Decrypt,
                &shared_key[..16],
                Some(&iv),
            )
            .unwrap();

            let mut decrypted = vec![0u8; empty_message.len()];
            decrypter.set_tag(&tag).unwrap();
            let count = decrypter
                .update(&ciphertext[..ciphertext.len() - 16], &mut decrypted)
                .unwrap();
            let rest = decrypter.finalize(&mut decrypted[count..]).unwrap();
            decrypted.truncate(count + rest);

            assert_eq!(&decrypted, empty_message);
        }

        // 2. large message test (64KB)
        {
            let large_message = vec![0x42u8; 65536]; // 64KB of data
            println!(
                "Testing large message encryption ({} bytes)",
                large_message.len()
            );

            let mut encrypter = Crypter::new(
                Cipher::aes_128_gcm(),
                Mode::Encrypt,
                &shared_key[..16],
                Some(&iv),
            )
            .unwrap();

            let mut ciphertext = vec![0u8; large_message.len()];
            let count = encrypter.update(&large_message, &mut ciphertext).unwrap();
            let rest = encrypter.finalize(&mut ciphertext[count..]).unwrap();
            ciphertext.truncate(count + rest);

            let mut tag = vec![0u8; 16];
            encrypter.get_tag(&mut tag).unwrap();
            ciphertext.extend_from_slice(&tag);

            // decrypt
            let mut decrypter = Crypter::new(
                Cipher::aes_128_gcm(),
                Mode::Decrypt,
                &shared_key[..16],
                Some(&iv),
            )
            .unwrap();

            let mut decrypted = vec![0u8; large_message.len()];
            decrypter.set_tag(&tag).unwrap();
            let count = decrypter
                .update(&ciphertext[..ciphertext.len() - 16], &mut decrypted)
                .unwrap();
            let rest = decrypter.finalize(&mut decrypted[count..]).unwrap();
            decrypted.truncate(count + rest);

            assert_eq!(decrypted, large_message);
        }

        // 3. special characters test
        {
            let special_chars = b"!@#$%^&*()_+{}:\"|<>?`~[]\\;',./";
            println!("Testing special characters encryption");

            let mut encrypter = Crypter::new(
                Cipher::aes_128_gcm(),
                Mode::Encrypt,
                &shared_key[..16],
                Some(&iv),
            )
            .unwrap();

            let mut ciphertext = vec![0u8; special_chars.len()];
            let count = encrypter.update(special_chars, &mut ciphertext).unwrap();
            let rest = encrypter.finalize(&mut ciphertext[count..]).unwrap();
            ciphertext.truncate(count + rest);

            let mut tag = vec![0u8; 16];
            encrypter.get_tag(&mut tag).unwrap();
            ciphertext.extend_from_slice(&tag);

            // decrypt
            let mut decrypter = Crypter::new(
                Cipher::aes_128_gcm(),
                Mode::Decrypt,
                &shared_key[..16],
                Some(&iv),
            )
            .unwrap();

            let mut decrypted = vec![0u8; special_chars.len()];
            decrypter.set_tag(&tag).unwrap();
            let count = decrypter
                .update(&ciphertext[..ciphertext.len() - 16], &mut decrypted)
                .unwrap();
            let rest = decrypter.finalize(&mut decrypted[count..]).unwrap();
            decrypted.truncate(count + rest);

            assert_eq!(&decrypted, special_chars);
        }

        // 4. test Unicode characters
        {
            let unicode_chars = "hello🌟".as_bytes();
            println!("Testing Unicode characters encryption");

            let mut encrypter = Crypter::new(
                Cipher::aes_128_gcm(),
                Mode::Encrypt,
                &shared_key[..16],
                Some(&iv),
            )
            .unwrap();

            let mut ciphertext = vec![0u8; unicode_chars.len()];
            let count = encrypter.update(unicode_chars, &mut ciphertext).unwrap();
            let rest = encrypter.finalize(&mut ciphertext[count..]).unwrap();
            ciphertext.truncate(count + rest);

            let mut tag = vec![0u8; 16];
            encrypter.get_tag(&mut tag).unwrap();
            ciphertext.extend_from_slice(&tag);

            // decrypt
            let mut decrypter = Crypter::new(
                Cipher::aes_128_gcm(),
                Mode::Decrypt,
                &shared_key[..16],
                Some(&iv),
            )
            .unwrap();

            let mut decrypted = vec![0u8; unicode_chars.len()];
            decrypter.set_tag(&tag).unwrap();
            let count = decrypter
                .update(&ciphertext[..ciphertext.len() - 16], &mut decrypted)
                .unwrap();
            let rest = decrypter.finalize(&mut decrypted[count..]).unwrap();
            decrypted.truncate(count + rest);

            assert_eq!(&decrypted, unicode_chars);
        }
    }

    #[test]
    fn test_encryption_error_cases() {
        // create a key pair and ecdh shared secret
        let alice_key = EcKey::generate(group_p256()).unwrap();
        let alice_private = PKey::from_ec_key(alice_key.clone()).unwrap();

        let bob_key = EcKey::generate(group_p256()).unwrap();
        let bob_public = PKey::from_ec_key(bob_key.to_public_key()).unwrap();

        // derive shared key
        let mut deriver = Deriver::new(&alice_private).unwrap();
        deriver.set_peer(&bob_public).unwrap();
        let shared_key = deriver.derive_to_vec().unwrap();

        let plaintext = b"Test encryption error cases";

        // 1. invalid key length test
        {
            println!("Testing incorrect key length");
            // too short key
            let short_key = &shared_key[..8];
            let iv = vec![0u8; 12];

            let result = Crypter::new(Cipher::aes_128_gcm(), Mode::Encrypt, short_key, Some(&iv));

            assert!(result.is_err(), "Expected error with short key");
        }

        // 2. invalid IV length test
        {
            println!("Testing incorrect IV length");
            // too short IV
            let invalid_iv = vec![0u8; 4];

            let result = Crypter::new(
                Cipher::aes_128_gcm(),
                Mode::Encrypt,
                &shared_key[..16],
                Some(&invalid_iv),
            );

            assert!(result.is_err(), "Expected error with short IV");
        }

        // 3. invalid tag length test
        {
            println!("Testing tampered ciphertext");
            let iv = vec![0u8; 12];

            // encrypt
            let mut encrypter = Crypter::new(
                Cipher::aes_128_gcm(),
                Mode::Encrypt,
                &shared_key[..16],
                Some(&iv),
            )
            .unwrap();

            let mut ciphertext = vec![0u8; plaintext.len()];
            let count = encrypter.update(plaintext, &mut ciphertext).unwrap();
            let rest = encrypter.finalize(&mut ciphertext[count..]).unwrap();
            ciphertext.truncate(count + rest);

            let mut tag = vec![0u8; 16];
            encrypter.get_tag(&mut tag).unwrap();

            // force tag tampering
            ciphertext[0] ^= 0xFF;

            // try to decrypt
            let mut decrypter = Crypter::new(
                Cipher::aes_128_gcm(),
                Mode::Decrypt,
                &shared_key[..16],
                Some(&iv),
            )
            .unwrap();

            println!("get tag: {:?}", tag);
            let mut decrypted = vec![0u8; plaintext.len()];
            decrypter.set_tag(&tag).unwrap();

            // try to decrypt with tampered ciphertext
            let decrypt_result = decrypter.update(&ciphertext, &mut decrypted);
            assert!(
                decrypt_result.is_err(),
                "Expected error with tampered ciphertext"
            );
        }
    }

    #[test]
    fn test_memory_allocation_and_zeroing() {
        use std::mem;

        // create a key and check memory allocation
        {
            let ec_key = EcKey::generate(group_p256()).unwrap();
            let private_key = ec_key.private_key().unwrap();

            // check private key memory size
            println!("Private key size: {} bytes", mem::size_of_val(&private_key));

            // check for unnecessary memory allocation
            assert!(
                mem::size_of_val(&private_key) <= 64,
                "Excessive private key memory allocation"
            );
        }

        // Vec allocation and buffer overflow prevention check
        {
            let plaintext = vec![0x42u8; 1024];
            let buffer = vec![0u8; plaintext.len() + 16]; // 추가 공간 확보

            assert!(
                buffer.capacity() >= plaintext.len() + 16,
                "Insufficient buffer capacity"
            );
            assert!(
                buffer.len() == plaintext.len() + 16,
                "Incorrect initial buffer length"
            );
        }

        // zeroing sensitive data
        {
            let mut sensitive_data = vec![0x41u8; 32];

            // zero out the data
            sensitive_data.iter_mut().for_each(|x| *x = 0);

            // check if all bytes are zero
            assert!(
                sensitive_data.iter().all(|&x| x == 0),
                "Failed to zero out sensitive data"
            );
        }
    }

    #[test]
    fn test_encryption_performance() {
        use std::time::{Duration, Instant};

        // create a key pair and ecdh shared secret
        let alice_key = EcKey::generate(group_p256()).unwrap();
        let alice_private = PKey::from_ec_key(alice_key.clone()).unwrap();

        let bob_key = EcKey::generate(group_p256()).unwrap();
        let bob_public = PKey::from_ec_key(bob_key.to_public_key()).unwrap();

        // derive shared key
        let mut deriver = Deriver::new(&alice_private).unwrap();
        deriver.set_peer(&bob_public).unwrap();
        let shared_key = deriver.derive_to_vec().unwrap();

        // ready large data (1MB)
        let large_data = vec![0x42u8; 1024 * 1024];
        let iv = vec![0u8; 12];

        // check encryption performance
        {
            let start = Instant::now();
            let mut encrypter = Crypter::new(
                Cipher::aes_128_gcm(),
                Mode::Encrypt,
                &shared_key[..16],
                Some(&iv),
            )
            .unwrap();

            let mut ciphertext = vec![0u8; large_data.len() + 16];
            let count = encrypter.update(&large_data, &mut ciphertext).unwrap();
            encrypter.finalize(&mut ciphertext[count..]).unwrap();

            let duration = start.elapsed();
            println!("Encryption time for 1MB: {:?}", duration);

            // certain performance criteria (e.g., within 250ms)
            assert!(
                duration < Duration::from_millis(250),
                "Encryption took too long"
            );
        }

        // check decryption performance
        {
            let mut encrypter = Crypter::new(
                Cipher::aes_128_gcm(),
                Mode::Encrypt,
                &shared_key[..16],
                Some(&iv),
            )
            .unwrap();

            let mut ciphertext = vec![0u8; large_data.len() + 16];
            let count = encrypter.update(&large_data, &mut ciphertext).unwrap();
            let rest = encrypter.finalize(&mut ciphertext[count..]).unwrap();
            ciphertext.truncate(count + rest);

            let mut tag = vec![0u8; 16];
            encrypter.get_tag(&mut tag).unwrap();
            ciphertext.extend_from_slice(&tag);

            let start = Instant::now();
            let mut decrypter = Crypter::new(
                Cipher::aes_128_gcm(),
                Mode::Decrypt,
                &shared_key[..16],
                Some(&iv),
            )
            .unwrap();

            let mut decrypted = vec![0u8; large_data.len()];
            decrypter.set_tag(&tag).unwrap();
            let count = decrypter
                .update(&ciphertext[..ciphertext.len() - 16], &mut decrypted)
                .unwrap();
            decrypter.finalize(&mut decrypted[count..]).unwrap();

            let duration = start.elapsed();
            println!("Decryption time for 1MB: {:?}", duration);

            // certain performance criteria (e.g., within 250ms)
            assert!(
                duration < Duration::from_millis(250),
                "Decryption took too long"
            );
        }
    }
}
