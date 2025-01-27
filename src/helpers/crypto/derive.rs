use num_bigint::BigUint;

use super::{
    ec::{pad_to_32_bytes, EcPoint, PKey, Private, Public, P256_FIELD_SIZE},
    group_p256,
};
use num_traits::Zero;

#[derive(Debug)]
pub struct Deriver {
    private_key: Vec<u8>,
    peer_key: Option<Vec<u8>>,
}

impl Deriver {
    pub fn new(private_key: &PKey<Private>) -> Result<Self, ece::Error> {
        // 1. compare the length of the key data
        if private_key.key_data.len() != 96 {
            // 32(private) + 32(x) + 32(y)
            println!("Invalid key length: {}", private_key.key_data.len());
            return Err(ece::Error::CryptoError);
        }

        // 2. extract the private key part (first 32 bytes)
        let priv_key_bytes = private_key.key_data[..32].to_vec();

        // 3. extract the public key part and validate
        let x = BigUint::from_bytes_be(&private_key.key_data[32..64]);
        let y = BigUint::from_bytes_be(&private_key.key_data[64..]);

        let group = group_p256();
        if !group.check_point(&x, &y) {
            println!("Point validation failed in Deriver::new");
            return Err(ece::Error::CryptoError);
        }

        Ok(Deriver {
            private_key: priv_key_bytes,
            peer_key: None,
        })
    }

    pub fn set_peer(&mut self, peer_key: &PKey<Public>) -> Result<(), ece::Error> {
        // check if peer key is already set
        if peer_key.key_data.len() != 64 {
            println!("peer_key.key_data.len() != 64");
            return Err(ece::Error::CryptoError);
        }

        // 1. check point validation
        let group = group_p256();
        let x = BigUint::from_bytes_be(&peer_key.key_data[..P256_FIELD_SIZE]);
        let y = BigUint::from_bytes_be(&peer_key.key_data[P256_FIELD_SIZE..]);

        // 2. curve equation validation
        if !group.check_point(&x, &y) {
            println!("Invalid point: curve equation failed");
            return Err(ece::Error::CryptoError);
        }

        // 3. check if the point is at infinity
        if x.is_zero() && y.is_zero() {
            println!("Invalid point: infinity point");
            return Err(ece::Error::CryptoError);
        }

        self.peer_key = Some(peer_key.key_data.clone());
        Ok(())
    }

    pub fn derive_to_vec(&self) -> Result<Vec<u8>, ece::Error> {
        let peer_key = self.peer_key.as_ref().ok_or(ece::Error::CryptoError)?;

        let group = group_p256();
        let p = group.prime();
        let n = group.order();

        // 1. try to convert the private key to BigUint
        let priv_key = BigUint::from_bytes_be(&self.private_key);
        if priv_key >= *n {
            println!("Private key out of range");
            return Err(ece::Error::CryptoError);
        }

        // 2. peer's public key to affine coordinates
        let peer_x = BigUint::from_bytes_be(&peer_key[..P256_FIELD_SIZE]);
        let peer_y = BigUint::from_bytes_be(&peer_key[P256_FIELD_SIZE..]);

        // 3. check if the peer's public key is on the curve
        if !group.check_point(&peer_x, &peer_y) {
            println!("Invalid peer point");
            return Err(ece::Error::CryptoError);
        }

        // 4. ECDH operation
        let peer_point =
            EcPoint::new(group, peer_x, peer_y).map_err(|_| ece::Error::CryptoError)?;
        let result = peer_point
            .scalar_mul(&priv_key)
            .map_err(|_| ece::Error::CryptoError)?;

        // 5. check if the result is the point at infinity
        if result.z.is_zero() {
            println!("Result is point at infinity");
            return Err(ece::Error::CryptoError);
        }

        // 6. x coordinate extraction and normalization
        let (shared_x, _) = result.get_affine().map_err(|_| ece::Error::CryptoError)?;
        let shared_x = shared_x % p;

        // 7. check range of the shared secret
        if shared_x >= *p {
            println!("Shared secret out of range");
            return Err(ece::Error::CryptoError);
        }

        // 8. convert the shared secret to bytes and pad to 32 bytes
        let result = pad_to_32_bytes(&shared_x).map_err(|_| ece::Error::CryptoError)?;

        // 9. check the length of the result
        if result.len() != 32 {
            println!("Invalid result length");
            return Err(ece::Error::CryptoError);
        }

        Ok(result)
    }
}
