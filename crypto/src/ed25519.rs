use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug)]
pub struct InvalidPrivateKey;

impl std::fmt::Display for InvalidPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid private key")
    }
}

impl std::error::Error for InvalidPrivateKey {}

#[derive(Debug)]
pub struct PrivateKey(ring::signature::Ed25519KeyPair);

impl PrivateKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let rand = ring::rand::SystemRandom::new();
        Ed25519KeyPair::generate_pkcs8(&rand)
            .unwrap()
            .as_ref()
            .to_vec()
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(
            TryFrom::try_from(self.0.public_key().as_ref())
                .expect("invalid ed25519 public key size"),
        )
    }
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        // UNSAFE: the type is just a bag of bytes that could implement clone/copy but for some
        // reason doesn't
        Self(unsafe { std::ptr::read(std::ptr::addr_of!(self.0)) })
    }
}

impl std::fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = hex::encode(self.to_bytes());
        f.write_str(&hex)
    }
}

impl std::str::FromStr for PrivateKey {
    type Err = InvalidPrivateKey;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pkcs8 = hex::decode(s).map_err(|_| InvalidPrivateKey)?;
        Ed25519KeyPair::from_pkcs8(&pkcs8)
            .map_err(|_| InvalidPrivateKey)
            .map(PrivateKey)
    }
}

#[derive(Debug)]
pub struct InvalidPublicKey;

impl std::fmt::Display for InvalidPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid public key")
    }
}

impl std::error::Error for InvalidPublicKey {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey([u8; ring::signature::ED25519_PUBLIC_KEY_LEN]);

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        <[u8; 32] as TryFrom<&[u8]>>::try_from(self.as_bytes())
            .unwrap()
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self(<[u8; 32] as Deserialize<'de>>::deserialize(
            deserializer,
        )?))
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = hex::encode(self.as_bytes());
        f.write_str(&hex)
    }
}

impl std::str::FromStr for PublicKey {
    type Err = InvalidPublicKey;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex = hex::decode(s).map_err(|_| InvalidPublicKey)?;
        Ok(Self(
            TryFrom::try_from(hex.as_slice()).map_err(|_| InvalidPublicKey)?,
        ))
    }
}

#[derive(Clone, Copy)]
pub struct Signature(ring::signature::Signature);

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = hex::encode(self.0.as_ref());
        f.debug_tuple("Signature").field(&hex).finish()
    }
}

impl std::cmp::PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}

impl std::cmp::Eq for Signature {}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let data = <Vec<u8> as Deserialize<'de>>::deserialize(deserializer)?;

        let sig = unsafe {
            type S = ring::signature::Signature;

            let sig_size = std::mem::size_of::<S>();
            let sig_value_max_size = sig_size - std::mem::size_of::<usize>();

            if data.len() > sig_value_max_size {
                return Err(D::Error::custom("invalid signature size"));
            }

            let mut sig = std::mem::zeroed::<S>();
            let sig_value: &[u8] = sig.as_ref();
            let sig_value_ptr = sig_value.as_ptr() as *mut u8;
            // this is fragile
            // this command reports the len field comes first
            // cargo +nightly rustc -- -Zprint-type-sizes
            let sig_len_ptr = ((&mut sig) as *mut S) as *mut usize;
            let sig_value_patched = std::slice::from_raw_parts_mut(sig_value_ptr, data.len());
            sig_value_patched.copy_from_slice(&data);
            *sig_len_ptr = data.len();

            assert_eq!(sig.as_ref().len(), data.len());
            assert_eq!(sig.as_ref(), &data);

            sig
        };

        Ok(Self(sig))
    }
}

impl Signature {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub fn generate() -> (PublicKey, PrivateKey) {
    let rng = ring::rand::SystemRandom::new();
    let key_pair = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(key_pair.as_ref()).unwrap();
    let private_key = PrivateKey(key_pair);
    let public_key = private_key.public_key();
    (public_key, private_key)
}

pub fn sign(key: &PrivateKey, data: &[u8]) -> Signature {
    Signature(key.0.sign(data))
}

pub fn verify(key: &PublicKey, data: &[u8], sig: &Signature) -> bool {
    let public_key =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key.0.as_ref());
    public_key.verify(data, sig.as_bytes()).is_ok()
}
