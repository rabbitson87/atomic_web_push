use aes_gcm::KeyInit;
use sha2::digest::generic_array::GenericArray;

use super::AES_GCM_TAG_LENGTH;

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Cipher {
    key_len: usize,
    block_size: usize,
    iv_len: usize,
}

impl Cipher {
    pub fn aes_128_gcm() -> Self {
        Cipher {
            key_len: 16,
            block_size: 16,
            iv_len: 12,
        }
    }

    pub fn block_size(&self) -> usize {
        self.block_size
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

pub struct Crypter {
    cipher: Cipher,
    mode: Mode,
    key: Vec<u8>,
    iv: Option<Vec<u8>>,
    buffer: Vec<u8>,
    tag: Option<Vec<u8>>,
}

impl Crypter {
    pub fn new(
        cipher: Cipher,
        mode: Mode,
        key: &[u8],
        iv: Option<&[u8]>,
    ) -> Result<Crypter, CryptoError> {
        if key.len() != cipher.key_len {
            return Err(CryptoError::InvalidKeyLength);
        }

        if let Some(iv) = iv {
            if iv.len() != cipher.iv_len {
                return Err(CryptoError::InvalidIVLength);
            }
        }

        Ok(Crypter {
            cipher,
            mode,
            key: key.to_vec(),
            iv: iv.map(|v| v.to_vec()),
            buffer: Vec::new(),
            tag: None,
        })
    }

    pub fn update(&mut self, data: &[u8], buf: &mut [u8]) -> Result<usize, CryptoError> {
        match self.mode {
            Mode::Encrypt => self.encrypt_update(data, buf),
            Mode::Decrypt => self.decrypt_update(data, buf),
        }
    }

    pub fn encrypt_update(&mut self, data: &[u8], buf: &mut [u8]) -> Result<usize, CryptoError> {
        use aes_gcm::{aead::Aead, Aes128Gcm};
        let key = GenericArray::from_slice(&self.key);
        let cipher = Aes128Gcm::new(key);
        let nonce = self.iv.as_ref().ok_or(CryptoError::MissingIV)?;
        let nonce = GenericArray::from_slice(nonce);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|_| CryptoError::EncryptionError)?;

        // extract tag (last 16 bytes)
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);
        self.tag = Some(tag.to_vec());

        if buf.len() < ct.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        buf[..ct.len()].copy_from_slice(ct);
        Ok(ct.len())
    }

    fn decrypt_update(&mut self, data: &[u8], buf: &mut [u8]) -> Result<usize, CryptoError> {
        use aes_gcm::{aead::Aead, Aes128Gcm};

        trace!("Step 1: Starting decrypt_update");
        trace!("Input data length: {}", data.len());

        let key = GenericArray::from_slice(&self.key);
        trace!("Step 2: Key setup complete, length: {}", self.key.len());

        let cipher = Aes128Gcm::new(key);
        let nonce = self.iv.as_ref().ok_or(CryptoError::MissingIV)?;
        trace!("Step 3: Nonce setup complete, length: {}", nonce.len());
        let nonce = GenericArray::from_slice(nonce);

        trace!("Step 4: Checking tag status");
        if let Some(ref tag) = self.tag {
            trace!("Tag is present, length: {}", tag.len());

            // 1. combine data and tag
            let mut complete_data = Vec::with_capacity(data.len() + tag.len());
            complete_data.extend_from_slice(data);
            complete_data.extend_from_slice(tag);

            trace!("Step 5: Combined data length: {}", complete_data.len());

            // 2. attempt decryption
            let plaintext = match cipher.decrypt(nonce, complete_data.as_slice()) {
                Ok(pt) => {
                    trace!(
                        "Step 6: Decryption successful, plaintext length: {}",
                        pt.len()
                    );
                    pt
                }
                Err(e) => {
                    error!("Step 6: Decryption failed: {:?}", e);
                    return Err(CryptoError::DecryptionError);
                }
            };

            // 3. copy result
            if buf.len() < plaintext.len() {
                error!("Step 7: Buffer too small");
                return Err(CryptoError::BufferTooSmall);
            }

            buf[..plaintext.len()].copy_from_slice(&plaintext);
            trace!("Step 8: Copy complete, returning {}", plaintext.len());
            Ok(plaintext.len())
        } else {
            trace!("Step 4b: No tag present, attempting to split data");
            // process data without tag
            if data.len() < 16 {
                error!("Step 5b: Data too short for splitting");
                return Err(CryptoError::DecryptionError);
            }

            let tag_start = data.len() - 16;
            let (ciphertext, tag) = data.split_at(tag_start);
            trace!(
                "Step 6b: Split complete - ciphertext: {}, tag: {}",
                ciphertext.len(),
                tag.len()
            );

            self.tag = Some(tag.to_vec());

            let plaintext = match cipher.decrypt(nonce, ciphertext) {
                Ok(pt) => {
                    trace!("Step 7b: Decryption successful, length: {}", pt.len());
                    pt
                }
                Err(e) => {
                    error!("Step 7b: Decryption failed: {:?}", e);
                    return Err(CryptoError::DecryptionError);
                }
            };

            if buf.len() < plaintext.len() {
                error!("Step 8b: Buffer too small");
                return Err(CryptoError::BufferTooSmall);
            }

            buf[..plaintext.len()].copy_from_slice(&plaintext);
            trace!("Step 9b: Copy complete, returning {}", plaintext.len());
            Ok(plaintext.len())
        }
    }

    pub fn finalize(&mut self, buf: &mut [u8]) -> Result<usize, CryptoError> {
        // GCM doesn't require padding
        Ok(0)
    }

    pub fn get_tag(&self, tag: &mut [u8]) -> Result<(), CryptoError> {
        if let Some(ref t) = self.tag {
            if tag.len() < t.len() {
                return Err(CryptoError::BufferTooSmall);
            }
            tag[..t.len()].copy_from_slice(t);
            Ok(())
        } else {
            Err(CryptoError::NoTag)
        }
    }

    pub fn set_tag(&mut self, tag: &[u8]) -> Result<(), CryptoError> {
        // 1. validate tag length (AES-GCM standard tag length is 16 bytes)
        if tag.len() != AES_GCM_TAG_LENGTH {
            return Err(CryptoError::InvalidTagLength);
        }

        // 2. validate tag triviality
        if !validate_tag(tag) {
            return Err(CryptoError::InvalidTagTrivial);
        }

        trace!("tag: {:?}", tag);

        self.tag = Some(tag.to_vec());
        Ok(())
    }
}

// validate tag function
pub fn validate_tag(tag: &[u8]) -> bool {
    // 1. basic validation
    if tag.len() != 16 {
        error!("Failed: Incorrect tag length");
        return false;
    }

    // 2. all bytes are the same (trivial tag)
    if tag.iter().all(|&x| x == tag[0]) {
        error!("Failed: All bytes are the same");
        return false;
    }

    // 3. sequential pattern check
    if tag.windows(2).all(|w| w[1] == w[0] + 1 || w[1] == w[0] - 1) {
        error!("Failed: Sequential pattern detected");
        return false;
    }

    // 4. unique byte count minimum
    let unique_bytes: std::collections::HashSet<u8> = tag.iter().cloned().collect();
    if unique_bytes.len() <= 4 {
        error!("Failed: Too few unique bytes ({})", unique_bytes.len());
        return false;
    }
    true
}

#[derive(Debug, PartialEq)]
pub enum CryptoError {
    InvalidTagTrivial,
    InvalidTagLength,
    InvalidKeyLength,
    InvalidIVLength,
    BufferTooSmall,
    EncryptionError,
    DecryptionError,
    MissingIV,
    NoTag,
}
