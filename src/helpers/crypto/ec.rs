use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

use super::bn::BigNumberHelper;

#[derive(Debug, Clone)]
pub struct EcGroup {
    // P-256 curve parameters
    pub p: BigUint,   // prime modulus
    pub a: BigUint,   // curve coefficient a
    pub b: BigUint,   // curve coefficient b
    pub g_x: BigUint, // generator x coordinate
    pub g_y: BigUint, // generator y coordinate
    pub n: BigUint,   // curve order
    pub h: BigUint,   // cofactor
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum Nid {
    X9_62_PRIME256V1,
}

impl EcGroup {
    pub fn from_curve_name(nid: Nid) -> Result<Self, EcError> {
        match nid {
            Nid::X9_62_PRIME256V1 => {
                // Prime modulus
                let p = BigUint::parse_bytes(
                    b"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
                    16,
                )
                .unwrap();

                let three = BigUint::from(3u32);
                let a = p.clone() - three;

                // curve parameter b
                let b = BigUint::parse_bytes(
                    b"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
                    16,
                )
                .unwrap();

                // Base point coordinates
                let g_x = BigUint::parse_bytes(
                    b"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
                    16,
                )
                .unwrap();
                let g_y = BigUint::parse_bytes(
                    b"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
                    16,
                )
                .unwrap();

                // curve order
                let n = BigUint::parse_bytes(
                    b"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
                    16,
                )
                .unwrap();

                Ok(EcGroup {
                    p,
                    a,
                    b,
                    g_x,
                    g_y,
                    n,
                    h: BigUint::from(1u32),
                })
            }
        }
    }

    pub fn check_point(&self, x: &BigUint, y: &BigUint) -> bool {
        let p = &self.p;

        // adjust coordinates to modulo p
        let x = x % p;
        let y = y % p;

        trace!("Point checking:");
        trace!("x: {}", x);
        trace!("y: {}", y);

        // y² mod p
        let y_squared = (&y * &y) % p;

        // x³ mod p
        let x_cubed = (x.modpow(&BigUint::from(3u32), p)) % p;

        // ax mod p
        let ax = (&self.a * &x) % p;

        // (x³ + ax + b) mod p
        let right_side = ((x_cubed + ax) % p + &self.b) % p;

        trace!("y² mod p: {}", y_squared);
        trace!("right side: {}", right_side);

        y_squared == right_side
    }

    pub fn generator(&'static self) -> Result<EcPoint, EcError> {
        EcPoint::new(self, self.g_x.clone(), self.g_y.clone())
    }

    pub fn order(&self) -> &BigUint {
        &self.n
    }

    pub fn prime(&self) -> &BigUint {
        &self.p
    }
}

#[derive(Debug)]
pub enum EcError {
    InvalidCurve,
    InvalidPoint,
    PointAtInfinity,
    InvalidPrivateKey,
    KeyPairMismatch,
}

// P-256 curve numbers
pub const P256_POINT_BYTES: usize = 65; // 1 byte (format) + 32 bytes (x) + 32 bytes (y)
pub const P256_FIELD_SIZE: usize = 32; // 256 bit = 32 bytes

#[derive(Debug)]
pub enum EcPointError {
    InvalidLength,
    InvalidFormat,
    InvalidPoint,
    PointAtInfinity,
}

// P-256 curve point format
#[derive(Clone, Debug)]
pub struct EcPoint {
    pub x: BigUint,
    pub y: BigUint,
    pub z: BigUint,
    pub group: &'static EcGroup,
}

#[derive(Debug, Clone, Copy)]
pub enum PointConversionForm {
    Compressed,   // 0x02 or 0x03 prefix
    Uncompressed, // 0x04 prefix
    Hybrid,       // 0x06 or 0x07 prefix
}

impl EcPoint {
    pub fn new(group: &'static EcGroup, x: BigUint, y: BigUint) -> Result<Self, EcError> {
        let p = &group.p;

        // 1. Normalize coordinates modulo p
        let x = &x % p;
        let y = &y % p;

        // 2. Check if the point is on the curve (y² = x³ + ax + b mod p)
        let y_squared = (y.clone() * y.clone()) % p;

        // calculate x³
        let x_cubed = {
            let x_squared = (x.clone() * x.clone()) % p;
            (x_squared * x.clone()) % p
        };

        // calculate -3x (p-3)x mod p
        let neg_3x = {
            let three_x = (x.clone() * 3u32) % p;
            if three_x == BigUint::zero() {
                BigUint::zero()
            } else {
                p - three_x
            }
        };

        // x³ - 3x + b
        let mut right = (x_cubed.clone() + neg_3x.clone()) % p;
        right = (right + &group.b) % p;

        trace!("Detailed point validation:");
        trace!("x = {}", x);
        trace!("y = {}", y);
        trace!("x³ mod p = {}", x_cubed);
        trace!("-3x mod p = {}", neg_3x);
        trace!("b = {}", group.b);
        trace!("y² mod p = {}", y_squared);
        trace!("right side (x³ - 3x + b mod p) = {}", right);

        if y_squared != right {
            error!("Invalid point: equation does not hold!");
            error!(
                "Difference: {}",
                if y_squared > right {
                    y_squared - right
                } else {
                    right - y_squared
                }
            );
            return Err(EcError::InvalidPoint);
        }

        // 3. Check if the point is at infinity
        if x >= *p || y >= *p {
            error!("Point coordinates out of range!");
            return Err(EcError::InvalidPoint);
        }

        Ok(Self {
            x: x.clone(),
            y: y.clone(),
            z: BigUint::one(),
            group,
        })
    }

    pub fn is_on_curve(&self) -> bool {
        // always on curve if point at infinity
        if self.z.is_zero() {
            return true;
        }

        // convert to affine coordinates
        if let Err(err) = self.get_affine() {
            error!("Err(err) {:?}", err);
            return false;
        };

        // validate y² = x³ + ax + b (mod p)
        let p = self.group.prime();

        let x = &self.x % p;
        let y = &self.y % p;
        // 1. calculate x³
        let x_squared = (&x * &x) % p;
        let x_cubed = (&x_squared * &x) % p;

        // 2. calculate ax (a = -3)
        let a = &self.group.a % p;
        let ax = (a.clone() * &x) % p;

        // 3. calculate x³ + ax
        let sum1 = (&x_cubed + &ax) % p;

        // 4. calculate right side (x³ + ax + b)
        let b = &self.group.b % p;
        let right = (&sum1 + b) % p;

        // 5. calculate y²
        let y_squared = (&y * &y) % p;

        trace!("Detailed check values:");
        trace!("x mod p: {}", x);
        trace!("y mod p: {}", y);
        trace!("a mod p: {}", a);
        trace!("x^2 mod p: {}", x_squared);
        trace!("x^3 mod p: {}", x_cubed);
        trace!("ax mod p: {}", ax);
        trace!("sum1 (x^3 + ax) mod p: {}", sum1);
        trace!("right side (x^3 + ax + b) mod p: {}", right);
        trace!("y^2 mod p: {}", y_squared);

        right == y_squared
    }

    pub fn from_bytes(group: &'static EcGroup, data: &[u8]) -> Result<Self, EcPointError> {
        // 1. validate length
        if data.len() != P256_POINT_BYTES {
            return Err(EcPointError::InvalidLength);
        }

        // 2. format validation (uncompressed point starts with 0x04)
        if data[0] != 0x04 {
            return Err(EcPointError::InvalidFormat);
        }

        // 3. x, y coordinates extraction
        let x_bytes = &data[1..P256_FIELD_SIZE + 1];
        let y_bytes = &data[P256_FIELD_SIZE + 1..P256_POINT_BYTES];

        let x = BigUint::from_bytes_be(x_bytes);
        let y = BigUint::from_bytes_be(y_bytes);

        Ok(Self::new(group, x, y).map_err(|_| EcPointError::InvalidPoint)?)
    }

    pub fn get_affine(&self) -> Result<(BigUint, BigUint), EcError> {
        if self.z.is_zero() {
            return Err(EcError::PointAtInfinity);
        }

        let p = &self.group.p;

        // calculate Z's inverse
        let z_inv = mod_inverse(&self.z, p).ok_or(EcError::InvalidPoint)?;

        // X, Y coordinates calculation
        let x_affine = (&self.x * &z_inv) % p;
        let y_affine = (&self.y * &z_inv) % p;

        Ok((x_affine, y_affine))
    }

    pub fn to_bytes(&self, form: PointConversionForm) -> Result<Vec<u8>, EcError> {
        let (x, y) = self.get_affine()?;

        match form {
            PointConversionForm::Uncompressed => {
                let mut result = vec![0u8; 65]; // 1 + 32 + 32 bytes
                result[0] = 0x04; // uncompressed point marker

                // x coordinate padding
                let x_bytes = pad_to_32_bytes(&x)?;
                result[1..33].copy_from_slice(&x_bytes);

                // y coordinate padding
                let y_bytes = pad_to_32_bytes(&y)?;
                result[33..65].copy_from_slice(&y_bytes);

                Ok(result)
            }
            PointConversionForm::Compressed => {
                let mut result = vec![if &y % 2u32 == BigUint::from(0u32) {
                    0x02
                } else {
                    0x03
                }];
                result.extend(pad_to_32_bytes(&x)?);
                Ok(result)
            }
            PointConversionForm::Hybrid => {
                let mut result = vec![if &y % 2u32 == BigUint::from(0u32) {
                    0x06
                } else {
                    0x07
                }];
                result.extend(pad_to_32_bytes(&x)?);
                result.extend(pad_to_32_bytes(&y)?);
                Ok(result)
            }
        }
    }

    pub fn affine_coordinates_gfp(
        &self,
        x: &mut BigNumberHelper,
        y: &mut BigNumberHelper,
    ) -> Result<(), EcError> {
        let (affine_x, affine_y) = self.get_affine()?;

        *x = BigNumberHelper::from_bytes(&affine_x.to_bytes_be());
        *y = BigNumberHelper::from_bytes(&affine_y.to_bytes_be());

        Ok(())
    }

    pub fn scalar_mul(&self, scalar: &BigUint) -> Result<Self, EcError> {
        // normalize scalar to order
        let order = self.group.order();
        let scalar = scalar % order;

        if scalar.is_zero() {
            return Err(EcError::PointAtInfinity);
        }

        let mut result = self.clone();
        for i in (0..scalar.bits()).rev() {
            if i != scalar.bits() - 1 {
                // first bit is not doubled
                result = result.double()?;
            }
            if scalar.bit(i) {
                result = result.add(self)?;
            }
        }

        // check if the result is at point infinity
        if result.z.is_zero() {
            return Err(EcError::PointAtInfinity);
        }

        Ok(result)
    }

    // point doubling operation (P + P)
    pub fn double(&self) -> Result<Self, EcError> {
        if self.z.is_zero() {
            return Ok(self.clone());
        }

        let p = self.group.prime();
        let (x, y) = self.get_affine()?;

        // Step 1: Calculate λ = (3x² - 3) / (2y)
        let two = BigUint::from(2u32);
        let three = BigUint::from(3u32);

        let x_squared = (&x * &x) % p;
        let three_x_squared = (&three * &x_squared) % p;
        let three_z_squared = BigUint::from(3u32); // Since z = 1 in affine coordinates

        let numerator = if three_x_squared >= three_z_squared {
            (three_x_squared - three_z_squared) % p
        } else {
            (p + three_x_squared - three_z_squared) % p
        };

        let two_y = (&two * &y) % p;
        let two_y_inv = mod_inverse(&two_y, p).ok_or(EcError::InvalidPoint)?;

        let lambda = (&numerator * &two_y_inv) % p;

        // Step 2: Calculate x₃ = λ² - 2x
        let lambda_squared = (&lambda * &lambda) % p;
        let two_x = (&two * &x) % p;
        let x3 = if lambda_squared >= two_x {
            (lambda_squared - two_x) % p
        } else {
            (p + lambda_squared - two_x) % p
        };

        // Step 3: Calculate y₃ = λ(x - x₃) - y
        let x_diff = if x >= x3 {
            (&x - &x3) % p
        } else {
            (p + &x - &x3) % p
        };

        let lambda_times_diff = (&lambda * &x_diff) % p;
        let y3 = if lambda_times_diff >= y {
            (lambda_times_diff - &y) % p
        } else {
            (p + lambda_times_diff - &y) % p
        };

        trace!("Double operation details:");
        trace!("Input (x,y): ({}, {})", x, y);
        trace!("λ calculation:");
        trace!("  numerator = 3x² - 3 = {}", numerator);
        trace!("  denominator = 2y = {}", two_y);
        trace!("  λ = {}", lambda);
        trace!("New point calculation:");
        trace!("  x₃ = λ² - 2x = {}", x3);
        trace!("  y₃ = λ(x - x₃) - y = {}", y3);

        let result = Self {
            x: x3.clone(),
            y: y3.clone(),
            z: BigUint::one(),
            group: self.group,
        };

        if !self.group.check_point(&x3, &y3) {
            error!("Double result validation failed!");
            error!("Point ({}, {}) is not on curve!", x3, y3);
            return Err(EcError::InvalidPoint);
        }

        Ok(result)
    }

    // point addition operation (P + Q)
    pub fn add(&self, other: &Self) -> Result<Self, EcError> {
        if self.z.is_zero() {
            return Ok(other.clone());
        }
        if other.z.is_zero() {
            return Ok(self.clone());
        }

        let p = self.group.prime();
        let (x1, y1) = self.get_affine()?;
        let (x2, y2) = other.get_affine()?;

        // Special case: P + (-P) = O (point at infinity)
        if x1 == x2 {
            if y1 == y2 {
                return self.double();
            }
            // 역원인 경우
            return Ok(Self {
                x: BigUint::zero(),
                y: BigUint::zero(),
                z: BigUint::zero(),
                group: self.group,
            });
        }

        // λ = (y2-y1)/(x2-x1)
        let y_diff = if y2 >= y1 {
            (&y2 - &y1) % p
        } else {
            (p + &y2 - &y1) % p
        };

        let x_diff = if x2 >= x1 {
            (&x2 - &x1) % p
        } else {
            (p + &x2 - &x1) % p
        };

        let x_diff_inv = mod_inverse(&x_diff, p).ok_or(EcError::InvalidPoint)?;
        let lambda = (&y_diff * &x_diff_inv) % p;

        // x3 = λ² - x1 - x2
        let lambda_squared = (&lambda * &lambda) % p;
        let x3 = ((&lambda_squared + p - &x1) % p + p - &x2) % p;

        // y3 = λ(x1 - x3) - y1
        let x_diff_new = if x1 >= x3 {
            (&x1 - &x3) % p
        } else {
            (p + &x1 - &x3) % p
        };

        let y3 = ((&lambda * &x_diff_new) % p + p - &y1) % p;

        trace!("Add operation details:");
        trace!("  Input points: ({}, {}), ({}, {})", x1, y1, x2, y2);
        trace!("  λ = {}", lambda);
        trace!("  Result: ({}, {})", x3, y3);

        Ok(Self {
            x: x3,
            y: y3,
            z: BigUint::one(),
            group: self.group,
        })
    }
}

impl PartialEq for EcPoint {
    fn eq(&self, other: &Self) -> bool {
        // compare points at infinity with z coordinate
        if self.z.is_zero() && other.z.is_zero() {
            return true;
        }
        if self.z.is_zero() || other.z.is_zero() {
            return false;
        }

        // compare affine coordinates
        match (self.get_affine(), other.get_affine()) {
            (Ok((x1, y1)), Ok((x2, y2))) => x1 == x2 && y1 == y2,
            _ => false,
        }
    }
}

fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let a = a % m;
    if a.is_zero() {
        return None;
    }

    let mut t = BigInt::zero();
    let mut newt = BigInt::one();
    let mut r = BigInt::from(m.clone());
    let mut newr = BigInt::from(a.clone());

    while !newr.is_zero() {
        let quotient = &r / &newr;
        (t, newt) = (newt.clone(), t - &quotient * &newt);
        (r, newr) = (newr.clone(), r - quotient * newr);
    }

    if r > BigInt::one() {
        return None;
    }

    while t < BigInt::zero() {
        t = t + BigInt::from(m.clone());
    }

    let result = t.to_biguint().unwrap() % m;

    // 역원 검증
    if (&a * &result) % m != BigUint::one() {
        return None;
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mod_inverse() {
        // Test case 1: 3 * 4 ≡ 1 (mod 11)
        let a = BigUint::from(3u32);
        let m = BigUint::from(11u32);
        let result = mod_inverse(&a, &m).unwrap();
        assert_eq!(result, BigUint::from(4u32));

        // Verify: (3 * 4) mod 11 should equal 1
        let product = (BigInt::from(a) * BigInt::from(result)) % BigInt::from(m.clone());
        assert_eq!(product, BigInt::one());

        // Test case 2: Zero input
        let a = BigUint::zero();
        let m = BigUint::from(5u32);
        assert_eq!(mod_inverse(&a, &m), None);

        // Test case 3: When no inverse exists (non-coprime numbers)
        let a = BigUint::from(2u32);
        let m = BigUint::from(4u32);
        assert_eq!(mod_inverse(&a, &m), None);

        // Test case 4: Large coprime numbers
        let a = BigUint::from(17u32);
        let m = BigUint::from(23u32);
        let result = mod_inverse(&a, &m).unwrap();
        let product = (BigInt::from(a) * BigInt::from(result)) % BigInt::from(m);
        assert_eq!(product, BigInt::one());
    }

    #[test]
    fn test_edge_cases() {
        // Test with 1
        let a = BigUint::from(1u32);
        let m = BigUint::from(7u32);
        assert_eq!(mod_inverse(&a, &m).unwrap(), BigUint::from(1u32));

        // Test with modulus - 1
        let a = BigUint::from(6u32); // 7 - 1
        let m = BigUint::from(7u32);
        assert_eq!(mod_inverse(&a, &m).unwrap(), BigUint::from(6u32));

        // Test with zero modulus
        let a = BigUint::from(5u32);
        let m = BigUint::zero();
        assert_eq!(mod_inverse(&a, &m), None);
    }
}

pub trait KeyType {}

#[derive(Debug, Clone)]
pub struct Private;

#[derive(Debug, Clone)]
pub struct Public;

impl KeyType for Private {}
impl KeyType for Public {}

use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct EcKey<T: KeyType> {
    group: &'static EcGroup,
    public_key: EcPoint,
    pub private_key: Option<BigUint>, // private key is only available for EcKey<Private>
    _phantom: PhantomData<T>,         // marker for key type
}

impl<T: KeyType> EcKey<T> {
    pub fn group(&self) -> &'static EcGroup {
        self.group
    }

    pub fn public_key(&self) -> &EcPoint {
        &self.public_key
    }
}

impl EcKey<Private> {
    // create a new key pair
    pub fn generate(group: &'static EcGroup) -> Result<Self, EcError> {
        // 1. generate private key with random value
        let private_key = generate_random_below(&group.order())?;

        // 2. calculate public key (G * private_key)
        let public_key = group.generator()?.scalar_mul(&private_key)?;

        Ok(Self {
            group,
            public_key,
            private_key: Some(private_key),
            _phantom: PhantomData,
        })
    }

    pub fn private_key(&self) -> Option<&BigUint> {
        self.private_key.as_ref()
    }

    pub fn to_public_key(&self) -> EcKey<Public> {
        EcKey {
            group: self.group,
            public_key: self.public_key.clone(),
            private_key: None,
            _phantom: PhantomData,
        }
    }

    pub fn from_private_components(
        group: &'static EcGroup,
        private_key: &BigNumberHelper,
        public_point: &EcPoint,
    ) -> Result<Self, EcError> {
        // validate private key in the correct range
        let private_biguint = BigUint::from_bytes_be(&private_key.to_bytes());
        if private_biguint >= *group.order() {
            return Err(EcError::InvalidPrivateKey);
        }

        // validate public point on the private key curve
        let computed_public = group.generator()?.scalar_mul(&private_biguint)?;
        if !computed_public.eq(public_point) {
            return Err(EcError::KeyPairMismatch);
        }

        Ok(Self {
            group,
            public_key: public_point.clone(),
            private_key: Some(private_biguint),
            _phantom: PhantomData,
        })
    }
}

impl EcKey<Public> {
    pub fn from_public_key(group: &'static EcGroup, public_key: EcPoint) -> Result<Self, EcError> {
        if !public_key.is_on_curve() {
            return Err(EcError::InvalidCurve);
        }

        Ok(Self {
            group,
            public_key,
            private_key: None,
            _phantom: PhantomData,
        })
    }

    pub fn from_public_key_affine_coordinates(
        group: &'static EcGroup,
        x: &BigNumberHelper,
        y: &BigNumberHelper,
    ) -> Result<Self, EcError> {
        let x_biguint = BigUint::from_bytes_be(&x.to_bytes());
        let y_biguint = BigUint::from_bytes_be(&y.to_bytes());

        // create point from affine coordinates
        let point = EcPoint::new(group, x_biguint, y_biguint)?;

        // create public key
        EcKey::from_public_key(group, point)
    }
}

pub fn pad_to_32_bytes(num: &BigUint) -> Result<Vec<u8>, EcError> {
    let bytes = num.to_bytes_be();
    if bytes.len() > 32 {
        return Err(EcError::InvalidPoint);
    }

    let mut result = vec![0; 32];
    result[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(result)
}

fn generate_random_below(max: &BigUint) -> Result<BigUint, EcError> {
    use rand::{thread_rng, RngCore};

    let mut rng = thread_rng();
    let byte_length = (max.bits() + 7) / 8;
    let mut bytes = vec![0u8; byte_length as usize];

    loop {
        rng.fill_bytes(&mut bytes);
        let value = BigUint::from_bytes_be(&bytes);
        if value < *max {
            return Ok(value);
        }
    }
}

#[derive(Debug)]
pub enum PKeyType {
    Public,
    Private,
}

#[derive(Debug)]
pub struct PKey<T> {
    pub key_data: Vec<u8>,
    key_type: PKeyType,
    _marker: PhantomData<T>,
}

pub trait KeyTypeMarker {}
impl KeyTypeMarker for Public {}
impl KeyTypeMarker for Private {}

impl<T: KeyTypeMarker> PKey<T> {
    pub fn new(key_data: Vec<u8>, key_type: PKeyType) -> Self {
        PKey {
            key_data,
            key_type,
            _marker: PhantomData,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.key_data
    }
}

impl<T: KeyType + KeyTypeMarker> PKey<T> {
    pub fn from_ec_key(ec_key: EcKey<T>) -> Result<Self, ece::Error> {
        let mut key_data = Vec::new();

        // 1. progress private key (if available)
        if let Some(priv_key) = ec_key.private_key.as_ref() {
            if priv_key >= ec_key.group().order() {
                return Err(ece::Error::CryptoError);
            }
            let priv_bytes = pad_to_32_bytes(priv_key).map_err(|_| ece::Error::CryptoError)?;
            key_data.extend_from_slice(&priv_bytes);
        }

        // 2. validate public key to be on the curve
        let public_key = ec_key.public_key();
        let (x, y) = public_key.get_affine().map_err(|e| {
            error!("Affine transformation error: {:?}", e);
            ece::Error::CryptoError
        })?;

        // 3. check if the point is at infinity증
        let group = ec_key.group();
        if !group.check_point(&x, &y) {
            error!("Public key is not on curve!");
            return Err(ece::Error::CryptoError);
        }

        // 4. convert coordinates to bytes
        let x_bytes = pad_to_32_bytes(&x).map_err(|_| ece::Error::CryptoError)?;
        let y_bytes = pad_to_32_bytes(&y).map_err(|_| ece::Error::CryptoError)?;

        key_data.extend_from_slice(&x_bytes);
        key_data.extend_from_slice(&y_bytes);

        Ok(Self {
            key_data,
            key_type: if ec_key.private_key.is_some() {
                PKeyType::Private
            } else {
                PKeyType::Public
            },
            _marker: PhantomData,
        })
    }
}
