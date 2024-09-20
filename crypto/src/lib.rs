mod aes;
mod blsag;
mod ed25519;
mod rsa;
mod sha256;

pub use aes::*;
pub use blsag::*;
// pub use ed25519::*;
pub use rsa::*;
pub use sha256::*;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let (pubkey, privkey) = generate();
        let data = b"hello";
        let encrypted = encrypt(&pubkey, data);
        let decrypted = decrypt(&privkey, &encrypted);
        assert_eq!(&data[..], decrypted.as_slice());
    }

    #[test]
    fn test_symmetric_encrypt_decrypt() {
        let key = symmetric_generate();
        let data = b"hello";
        let encrypted = symmetric_encrypt(&key, &data[..]);
        let decrypted = symmetric_decrypt(&key, &encrypted);
        assert_eq!(&data[..], decrypted.as_slice());
    }
}
