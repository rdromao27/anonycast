use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use nazgul::{
    blsag::BLSAG,
    traits::{Sign, Verify},
};
use rand::rngs::OsRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha512;

// TODO: ???
const SECRET_INDEX: usize = 1;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Ring(Vec<RingPublicKey>);

impl From<Vec<RingPublicKey>> for Ring {
    fn from(value: Vec<RingPublicKey>) -> Self {
        Self(value)
    }
}

impl From<Ring> for Vec<RingPublicKey> {
    fn from(value: Ring) -> Self {
        value.0
    }
}

#[derive(Debug)]
pub struct InvalidRingPrivateKey;

impl std::fmt::Display for InvalidRingPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid ring private key")
    }
}

impl std::error::Error for InvalidRingPrivateKey {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingPrivateKey(Scalar);

impl RingPrivateKey {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn public_key(&self) -> RingPublicKey {
        RingPublicKey(self.0 * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT)
    }
}

impl std::fmt::Display for RingPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = hex::encode(self.as_bytes());
        f.write_str(&hex)
    }
}

impl std::str::FromStr for RingPrivateKey {
    type Err = InvalidRingPrivateKey;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = hex::decode(s).map_err(|_| InvalidRingPrivateKey)?;
        Ok(Self(Scalar::from_bytes_mod_order(
            TryFrom::try_from(decoded).map_err(|_| InvalidRingPrivateKey)?,
        )))
    }
}

#[derive(Debug)]
pub struct InvalidRingPublicKey;

impl std::fmt::Display for InvalidRingPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid ring public key")
    }
}

impl std::error::Error for InvalidRingPublicKey {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingPublicKey(RistrettoPoint);

impl RingPublicKey {
    pub fn into_bytes(&self) -> [u8; 32] {
        self.0.compress().0
    }
}

impl std::fmt::Display for RingPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = hex::encode(self.into_bytes());
        f.write_str(&hex)
    }
}

impl std::str::FromStr for RingPublicKey {
    type Err = InvalidRingPublicKey;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = hex::decode(s).map_err(|_| InvalidRingPublicKey)?;
        let compressed =
            CompressedRistretto::from_slice(&decoded).map_err(|_| InvalidRingPublicKey)?;
        compressed
            .decompress()
            .ok_or(InvalidRingPublicKey)
            .map(Self)
    }
}

impl Serialize for RingPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.into_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RingPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        let compressed = CompressedRistretto::from_slice(&bytes)
            .map_err(|_| D::Error::custom("invalid ring public key"))?;
        compressed
            .decompress()
            .ok_or_else(|| D::Error::custom("invalid ring public key"))
            .map(Self)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct RingSignatureSerdeProxy {
    challenge: [u8; 32],
    responses: Vec<[u8; 32]>,
    ring: Vec<[u8; 32]>,
    key_image: [u8; 32],
}

impl From<RingSignatureSerdeProxy> for RingSignature {
    fn from(value: RingSignatureSerdeProxy) -> Self {
        Self(BLSAG {
            challenge: Scalar::from_bytes_mod_order(value.challenge),
            responses: value
                .responses
                .into_iter()
                .map(Scalar::from_bytes_mod_order)
                .collect(),
            // TODO: remove unwraps by using TryFrom
            ring: value
                .ring
                .into_iter()
                .map(|r| {
                    CompressedRistretto::from_slice(&r)
                        .unwrap()
                        .decompress()
                        .unwrap()
                })
                .collect(),
            key_image: CompressedRistretto::from_slice(&value.key_image)
                .unwrap()
                .decompress()
                .unwrap(),
        })
    }
}

impl From<RingSignature> for RingSignatureSerdeProxy {
    fn from(value: RingSignature) -> Self {
        Self {
            challenge: value.0.challenge.to_bytes(),
            responses: value
                .0
                .responses
                .iter()
                .map(|s| s.to_bytes())
                .collect::<Vec<_>>(),
            ring: value
                .0
                .ring
                .iter()
                .map(|r| r.compress().to_bytes())
                .collect::<Vec<_>>(),
            key_image: value.0.key_image.compress().to_bytes(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(from = "RingSignatureSerdeProxy", into = "RingSignatureSerdeProxy")]
pub struct RingSignature(BLSAG);

impl Clone for RingSignature {
    fn clone(&self) -> Self {
        Self(BLSAG {
            challenge: self.0.challenge,
            responses: self.0.responses.clone(),
            ring: self.0.ring.clone(),
            key_image: self.0.key_image,
        })
    }
}

impl std::fmt::Debug for RingSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RingSignature").finish()
    }
}

pub fn ring_generate() -> (RingPublicKey, RingPrivateKey) {
    // https://docs.rs/nazgul/1.0.0/src/nazgul/blsag.rs.html#199
    let mut csprng = OsRng;
    let k: Scalar = Scalar::random(&mut csprng);
    let private_key = RingPrivateKey(k);
    let public_key = private_key.public_key();
    (public_key, private_key)
}

pub fn ring_sign(key: &RingPrivateKey, ring: &Ring, data: &[u8]) -> RingSignature {
    let signer_pk = key.public_key().0;
    let ring = ring
        .0
        .clone()
        .into_iter()
        .map(|pk| pk.0)
        .filter(|pk| pk != &signer_pk)
        .collect();
    let data = data.to_owned();
    RingSignature(BLSAG::sign::<Sha512, OsRng>(
        key.0,
        ring,
        SECRET_INDEX,
        &data,
    ))
}

pub fn ring_verify(ring: &Ring, data: &[u8], signature: &RingSignature) -> bool {
    if ring.0.len() != signature.0.ring.len()
        || !ring
            .0
            .iter()
            .map(|pk| pk.0)
            .all(|pk| signature.0.ring.contains(&pk))
    {
        return false;
    }
    let data = data.to_owned();
    let signature = signature.clone();
    BLSAG::verify::<Sha512>(signature.0, &data)
}

#[cfg(test)]
mod test {
    use super::*;

    const DATA_0: &[u8] = b"message 0";
    const DATA_1: &[u8] = b"message 1";

    #[test]
    fn sign_verify() {
        let (pub0, priv0) = ring_generate();
        let (pub1, _priv1) = ring_generate();
        let (pub2, _priv2) = ring_generate();
        let (pub3, _priv3) = ring_generate();

        {
            let ring = Ring::from(vec![pub0, pub1, pub2, pub3]);
            let sig = ring_sign(&priv0, &ring, DATA_0);
            assert!(ring_verify(&ring, DATA_0, &sig));
        }

        {
            let ring = Ring::from(vec![pub0, pub1, pub2, pub3]);
            let sig = ring_sign(&priv0, &ring, DATA_0);
            assert!(!ring_verify(&ring, DATA_1, &sig));
        }

        {
            let ring = Ring::from(vec![pub0, pub1, pub2, pub3]);
            let sig = ring_sign(&priv0, &ring, DATA_1);
            assert!(!ring_verify(&ring, DATA_0, &sig));
        }

        {
            let ring = Ring::from(vec![pub1, pub2, pub3]);
            let sig = ring_sign(&priv0, &ring, DATA_1);
            assert!(!ring_verify(&ring, DATA_0, &sig));
        }
    }

    #[test]
    fn from_str() {
        let (pub0, priv0) = ring_generate();

        let pub0_str = pub0.to_string();
        let pub0_parsed = pub0_str.parse::<RingPublicKey>().unwrap();
        assert_eq!(pub0, pub0_parsed);

        let priv0_str = priv0.to_string();
        let priv0_parsed = priv0_str.parse::<RingPrivateKey>().unwrap();
        assert_eq!(priv0, priv0_parsed);
    }
}
