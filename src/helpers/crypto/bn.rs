use num_bigint::BigUint;
use num_traits::{One, Zero};

pub struct BigNumberHelper {
    value: BigUint,
}

impl BigNumberHelper {
    pub fn new() -> Self {
        Self {
            value: BigUint::zero(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            value: BigUint::from_bytes_be(bytes),
        }
    }

    pub fn create_zero() -> BigUint {
        BigUint::zero()
    }

    pub fn create_one() -> BigUint {
        BigUint::one()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.value.to_bytes_be()
    }

    pub fn to_hex(value: &BigUint) -> String {
        format!("{:x}", value)
    }

    pub fn to_biguint(&self) -> BigUint {
        self.value.clone()
    }
}

impl From<BigUint> for BigNumberHelper {
    fn from(value: BigUint) -> Self {
        Self { value }
    }
}

impl From<BigNumberHelper> for BigUint {
    fn from(helper: BigNumberHelper) -> Self {
        helper.value
    }
}
