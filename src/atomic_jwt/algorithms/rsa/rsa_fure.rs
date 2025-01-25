use std::error::Error as StdError;
use std::fmt;

use p256::pkcs8::EncodePrivateKey;
use p256::pkcs8::EncodePublicKey;
use rsa::{pkcs1, pkcs8, traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};

#[derive(Debug)]
pub enum Error {
    RsaError(rsa::Error),
    Utf8Error(core::str::Utf8Error),
    Pkcs1Error(rsa::pkcs1::Error),
    Pkcs8Error(rsa::pkcs8::Error),
    SpkiError(rsa::pkcs8::spki::Error),
}

impl StdError for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::RsaError(e) => write!(f, "RSA error: {}", e),
            Error::Utf8Error(e) => write!(f, "UTF-8 error: {}", e),
            Error::Pkcs1Error(e) => write!(f, "PKCS#1 error: {}", e),
            Error::Pkcs8Error(e) => write!(f, "PKCS#8 error: {}", e),
            Error::SpkiError(e) => write!(f, "SPKI error: {}", e),
        }
    }
}

impl From<rsa::Error> for Error {
    fn from(e: rsa::Error) -> Self {
        Error::RsaError(e)
    }
}

impl From<core::str::Utf8Error> for Error {
    fn from(e: core::str::Utf8Error) -> Self {
        Error::Utf8Error(e)
    }
}

impl From<rsa::pkcs1::Error> for Error {
    fn from(e: rsa::pkcs1::Error) -> Self {
        Error::Pkcs1Error(e)
    }
}

impl From<rsa::pkcs8::Error> for Error {
    fn from(e: rsa::pkcs8::Error) -> Self {
        Error::Pkcs8Error(e)
    }
}

impl From<rsa::pkcs8::spki::Error> for Error {
    fn from(e: rsa::pkcs8::spki::Error) -> Self {
        Error::SpkiError(e)
    }
}

pub mod bn {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct BigNum(pub(crate) Vec<u8>);

    impl BigNum {
        pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
            Ok(BigNum(data.to_vec()))
        }

        pub fn to_vec(&self) -> Vec<u8> {
            self.0.clone()
        }
    }
}

pub mod hash {
    pub struct MessageDigest(pub(crate) DigestType);

    #[derive(Clone)]
    pub(crate) enum DigestType {
        Sha256,
        Sha384,
        Sha512,
    }

    impl MessageDigest {
        pub fn sha256() -> Self {
            MessageDigest(DigestType::Sha256)
        }

        pub fn sha384() -> Self {
            MessageDigest(DigestType::Sha384)
        }

        pub fn sha512() -> Self {
            MessageDigest(DigestType::Sha512)
        }
    }
}

pub mod sign {
    use pkey::PKey;
    use rsa_fure::{Padding, Rsa};

    use super::*;

    pub struct Signer<'a> {
        key: &'a PKey<Rsa<rsa_fure::Private>>,
        padding: Padding,
        digest: hash::MessageDigest, // digest 추가
        message: Vec<u8>,            // 메시지 저장용
    }

    impl<'a> Signer<'a> {
        pub fn new(
            digest: hash::MessageDigest,
            key: &'a PKey<Rsa<rsa_fure::Private>>,
        ) -> Result<Self, Error> {
            Ok(Self {
                key,
                padding: Padding::PKCS1,
                digest,
                message: Vec::new(),
            })
        }

        pub fn set_rsa_padding(&mut self, padding: Padding) -> Result<(), Error> {
            self.padding = padding;
            Ok(())
        }

        pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
            self.message.extend_from_slice(data);
            Ok(())
        }

        pub fn sign_to_vec(&self) -> Result<Vec<u8>, Error> {
            let private_key = RsaPrivateKey::from(self.key.inner.as_ref().clone());
            let mut rng = rand::thread_rng();
            Ok(match self.padding {
                Padding::PKCS1 => private_key
                    .sign(rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha256>(), &self.message)?,
                Padding::PKCS1_PSS => {
                    let padding = rsa::pss::Pss::new::<rsa::sha2::Sha256>();
                    private_key.sign_with_rng(&mut rng, padding, &self.message)?
                }
            })
        }
    }

    pub struct Verifier<'a> {
        key: &'a PKey<Rsa<rsa_fure::Public>>,
        padding: Padding,
        digest: hash::MessageDigest, // digest 추가
        message: Vec<u8>,            // 메시지 저장용
    }

    impl<'a> Verifier<'a> {
        pub fn new(
            digest: hash::MessageDigest,
            key: &'a PKey<Rsa<rsa_fure::Public>>,
        ) -> Result<Self, Error> {
            Ok(Self {
                key,
                padding: crate::atomic_jwt::algorithms::rsa::Padding::PKCS1,
                digest,
                message: Vec::new(),
            })
        }

        pub fn set_rsa_padding(
            &mut self,
            padding: crate::atomic_jwt::algorithms::rsa::Padding,
        ) -> Result<(), Error> {
            self.padding = padding;
            Ok(())
        }

        pub fn update(&mut self, _data: &[u8]) -> Result<(), Error> {
            Ok(())
        }

        pub fn verify(&self, signature: &[u8]) -> Result<bool, Error> {
            match self.padding {
                crate::atomic_jwt::algorithms::rsa::Padding::PKCS1 => {
                    RsaPublicKey::from(self.key.as_ref().as_ref().clone())
                        .verify(
                            rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha256>(),
                            &[],
                            signature,
                        )
                        .map(|_| true)
                        .or(Ok(false))
                }
                crate::atomic_jwt::algorithms::rsa::Padding::PKCS1_PSS => {
                    let salt_len = 0;
                    let padding = rsa::pss::Pss::new_with_salt::<rsa::sha2::Sha256>(salt_len);
                    RsaPublicKey::from(self.key.as_ref().as_ref().clone())
                        .verify(padding, &[], signature)
                        .map(|_| true)
                        .or(Ok(false))
                }
            }
        }
    }
}

pub mod rsa_fure {
    use pkcs1::DecodeRsaPublicKey;
    use pkcs8::{DecodePrivateKey, DecodePublicKey};

    use super::*;

    #[derive(Debug, Clone)]
    pub struct Public(RsaPublicKey);

    #[derive(Debug, Clone)]
    pub struct Private(RsaPrivateKey);

    #[derive(Debug, Clone, Copy)]
    pub enum Padding {
        PKCS1,
        PKCS1_PSS,
    }

    impl Public {
        pub fn public_key_from_der(der: &[u8]) -> Result<Self, Error> {
            RsaPublicKey::from_pkcs1_der(der)
                .map(Public)
                .map_err(Error::from)
        }

        pub fn public_key_from_der_pkcs1(der: &[u8]) -> Result<Self, Error> {
            RsaPublicKey::from_pkcs1_der(der)
                .map(Public)
                .map_err(Error::from)
        }

        pub fn public_key_from_pem(pem: &[u8]) -> Result<Self, Error> {
            RsaPublicKey::from_public_key_pem(core::str::from_utf8(pem)?)
                .map(Public)
                .map_err(Error::from)
        }

        pub fn public_key_from_pem_pkcs1(pem: &[u8]) -> Result<Self, Error> {
            RsaPublicKey::from_pkcs1_pem(core::str::from_utf8(pem)?)
                .map(Public)
                .map_err(Error::from)
        }

        pub fn from_public_components(n: bn::BigNum, e: bn::BigNum) -> Result<Self, Error> {
            let n = rsa::BigUint::from_bytes_be(&n.0);
            let e = rsa::BigUint::from_bytes_be(&e.0);
            RsaPublicKey::new(n, e).map(Public).map_err(Error::from)
        }

        pub fn public_key_to_der(&self) -> Result<Vec<u8>, Error> {
            Ok(self.0.to_public_key_der().map_err(Error::from)?.to_vec())
        }

        pub fn public_key_to_pem(&self) -> Result<Vec<u8>, Error> {
            Ok(self
                .0
                .to_public_key_pem(rsa::pkcs8::LineEnding::LF)?
                .into_bytes())
        }

        pub fn n(&self) -> bn::BigNum {
            bn::BigNum(self.0.n().to_bytes_be())
        }

        pub fn e(&self) -> bn::BigNum {
            bn::BigNum(self.0.e().to_bytes_be())
        }
    }
    impl From<Public> for RsaPublicKey {
        fn from(public: Public) -> RsaPublicKey {
            public.0
        }
    }

    impl From<RsaPublicKey> for Public {
        fn from(key: RsaPublicKey) -> Public {
            Public(key)
        }
    }

    impl Private {
        pub fn private_key_from_der(der: &[u8]) -> Result<Self, Error> {
            RsaPrivateKey::from_pkcs8_der(der)
                .map(Private)
                .map_err(Error::from)
        }

        pub fn private_key_from_pem(pem: &[u8]) -> Result<Self, Error> {
            RsaPrivateKey::from_pkcs8_pem(core::str::from_utf8(pem)?)
                .map(Private)
                .map_err(Error::from)
        }

        pub fn private_key_to_der(&self) -> Result<Vec<u8>, Error> {
            Ok(self
                .0
                .to_pkcs8_der()
                .map_err(Error::from)?
                .to_bytes()
                .to_vec())
        }

        pub fn private_key_to_pem(&self) -> Result<Vec<u8>, Error> {
            Ok(self
                .0
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?
                .to_string()
                .into_bytes())
        }

        pub fn generate(bits: u32) -> Result<Self, Error> {
            let mut rng = rand::thread_rng();
            RsaPrivateKey::new(&mut rng, bits as usize)
                .map(Private)
                .map_err(Error::from)
        }

        pub fn check_key(&self) -> Result<bool, Error> {
            Ok(true)
        }

        pub fn n(&self) -> Option<bn::BigNum> {
            Some(bn::BigNum(self.0.n().to_bytes_be()))
        }

        pub fn e(&self) -> Option<bn::BigNum> {
            Some(bn::BigNum(self.0.e().to_bytes_be()))
        }
    }
    impl From<Private> for RsaPrivateKey {
        fn from(private: Private) -> RsaPrivateKey {
            private.0
        }
    }

    impl From<RsaPrivateKey> for Private {
        fn from(key: RsaPrivateKey) -> Private {
            Private(key)
        }
    }
    #[derive(Debug, Clone)]
    pub struct Rsa<T: ?Sized> {
        inner: T,
    }

    impl<T> Rsa<T> {
        pub(crate) fn new(inner: T) -> Self {
            Rsa { inner }
        }
    }

    impl<T> AsRef<T> for Rsa<T> {
        fn as_ref(&self) -> &T {
            &self.inner
        }
    }

    impl Rsa<Private> {
        pub fn private_key_from_der(der: &[u8]) -> Result<Self, Error> {
            RsaPrivateKey::from_pkcs8_der(der)
                .map(Private)
                .map(Rsa::new)
                .map_err(Error::from)
        }

        pub fn private_key_from_pem(pem: &[u8]) -> Result<Self, Error> {
            let private = rsa_fure::Private::private_key_from_pem(pem)?;
            Ok(Rsa { inner: private })
        }

        pub fn private_key_to_der(&self) -> Result<Vec<u8>, Error> {
            self.inner.private_key_to_der()
        }

        pub fn private_key_to_pem(&self) -> Result<Vec<u8>, Error> {
            self.inner.private_key_to_pem()
        }

        pub fn check_key(&self) -> Result<bool, Error> {
            self.inner.check_key()
        }

        pub fn generate(bits: u32) -> Result<Self, Error> {
            let mut rng = rand::thread_rng();
            RsaPrivateKey::new(&mut rng, bits as usize)
                .map(Private)
                .map(Rsa::new)
                .map_err(Error::from)
        }

        pub fn n(&self) -> Result<bn::BigNum, Error> {
            match self.inner.n() {
                Some(n) => Ok(n),
                None => Err(rsa::Error::Internal.into()),
            }
        }

        pub fn e(&self) -> Result<bn::BigNum, Error> {
            match self.inner.e() {
                Some(e) => Ok(e),
                None => Err(rsa::Error::Internal.into()),
            }
        }
    }

    impl Rsa<Public> {
        pub fn public_key_from_der(der: &[u8]) -> Result<Self, Error> {
            RsaPublicKey::from_public_key_der(der)
                .map(Public)
                .map(Rsa::new)
                .map_err(Error::from)
        }

        pub fn public_key_from_der_pkcs1(der: &[u8]) -> Result<Self, Error> {
            RsaPublicKey::from_pkcs1_der(der)
                .map(Public)
                .map(Rsa::new)
                .map_err(Error::from)
        }

        pub fn public_key_from_pem(pem: &[u8]) -> Result<Self, Error> {
            RsaPublicKey::from_public_key_pem(core::str::from_utf8(pem)?)
                .map(Public)
                .map(Rsa::new)
                .map_err(Error::from)
        }

        pub fn public_key_from_pem_pkcs1(pem: &[u8]) -> Result<Self, Error> {
            RsaPublicKey::from_pkcs1_pem(core::str::from_utf8(pem)?)
                .map(Public)
                .map(Rsa::new)
                .map_err(Error::from)
        }

        pub fn from_public_components(n: bn::BigNum, e: bn::BigNum) -> Result<Self, Error> {
            let public = rsa_fure::Public::from_public_components(n, e)?;
            Ok(Rsa { inner: public })
        }

        pub fn public_key_to_der(&self) -> Result<Vec<u8>, Error> {
            self.inner.public_key_to_der()
        }

        pub fn public_key_to_pem(&self) -> Result<Vec<u8>, Error> {
            self.inner.public_key_to_pem()
        }

        pub fn n(&self) -> Vec<u8> {
            self.inner.n().0
        }

        pub fn e(&self) -> Vec<u8> {
            self.inner.e().0
        }
    }
}

pub mod pkey {
    use super::*;
    use std::any::Any;

    pub trait Private: Any {
        fn as_any(&self) -> &dyn Any;
        fn private_key_to_der(&self) -> Result<Vec<u8>, Error>;
        fn private_key_to_pem(&self) -> Result<Vec<u8>, Error>;
        fn check_key(&self) -> Result<bool, Error>;
    }

    pub trait Public: Any {
        fn as_any(&self) -> &dyn Any;
        fn public_key_to_der(&self) -> Result<Vec<u8>, Error>;
        fn public_key_to_pem(&self) -> Result<Vec<u8>, Error>;
        fn n(&self) -> Result<bn::BigNum, Error>;
        fn e(&self) -> Result<bn::BigNum, Error>;
    }

    impl Private for rsa_fure::Private {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn private_key_to_der(&self) -> Result<Vec<u8>, Error> {
            rsa_fure::Private::private_key_to_der(self)
        }

        fn private_key_to_pem(&self) -> Result<Vec<u8>, Error> {
            rsa_fure::Private::private_key_to_pem(self)
        }

        fn check_key(&self) -> Result<bool, Error> {
            rsa_fure::Private::check_key(self)
        }
    }

    impl Public for rsa_fure::Public {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn public_key_to_der(&self) -> Result<Vec<u8>, Error> {
            rsa_fure::Public::public_key_to_der(self)
        }

        fn public_key_to_pem(&self) -> Result<Vec<u8>, Error> {
            rsa_fure::Public::public_key_to_pem(self)
        }

        fn n(&self) -> Result<bn::BigNum, Error> {
            Ok(rsa_fure::Public::n(self))
        }

        fn e(&self) -> Result<bn::BigNum, Error> {
            Ok(rsa_fure::Public::e(self))
        }
    }

    pub struct PKey<T: ?Sized> {
        pub(crate) inner: T,
    }

    impl<T> PKey<T> {
        pub fn from_rsa(rsa: T) -> Result<Self, Error> {
            Ok(PKey { inner: rsa })
        }
    }

    impl<T> AsRef<T> for PKey<T> {
        fn as_ref(&self) -> &T {
            &self.inner
        }
    }
}
