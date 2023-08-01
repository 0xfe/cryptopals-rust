use crate::util::*;
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};

/// Encrypts a single block of plaintext using AES-128.
pub fn aes128_encrypt_block(block: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(block.len(), 16);
    assert_eq!(key.len(), 16);
    let cipher = aes::Aes128::new_from_slice(key).unwrap();
    let mut block = *GenericArray::from_slice(block);
    cipher.encrypt_block(&mut block);
    block.to_vec()
}

/// Decrypts a single block of ciphertext using AES-128.
pub fn aes128_decrypt_block(block: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(block.len(), 16);
    assert_eq!(key.len(), 16);
    let cipher = aes::Aes128::new_from_slice(key).unwrap();
    let mut block = *GenericArray::from_slice(block);
    cipher.decrypt_block(&mut block);
    block.to_vec()
}

/// Encrypts a byte slice using AES-128 in CBC mode.
pub fn aes128_cbc_encrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    assert_eq!(input.len() % 16, 0);
    let mut output = Vec::new();
    let mut prev = iv.to_vec();

    for chunk in input.chunks(16) {
        let mut block = xor_block(prev.as_slice(), chunk);
        block = aes128_encrypt_block(block.as_slice(), key);
        output.append(&mut block.clone());
        prev = block;
    }

    output
}

/// Decrypts a byte slice using AES-128 in CBC mode.
pub fn aes128_cbc_decrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    assert_eq!(input.len() % 16, 0);
    let mut output = Vec::new();
    let mut next = iv.to_vec();

    for chunk in input.chunks(16) {
        let block = aes128_decrypt_block(chunk, key);
        let mut block = xor_block(next.as_slice(), block.as_slice());
        output.append(&mut block);
        next = chunk.to_vec();
    }

    output
}

pub fn aes128_ecb_encrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(input.len() % 16, 0);
    input
        .chunks(16)
        .map(|chunk| aes128_encrypt_block(chunk, key))
        .flatten()
        .collect()
}

pub fn aes128_ecb_decrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(input.len() % 16, 0);
    input
        .chunks(16)
        .map(|chunk| aes128_decrypt_block(chunk, key))
        .flatten()
        .collect()
}

mod test {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_aes128_cbc() {
        let plaintext =
            "Hello hello, my name is Inigo Montoya. You killed my father. Prepare to die."
                .as_bytes();

        let key = "YELLOW SUBMARINE".as_bytes();
        let iv = vec![0; 16];

        let ciphertext =
            aes128_cbc_encrypt(pkcs7_pad(plaintext, 16).as_slice(), key, iv.as_slice());
        let plaintext2 = aes128_cbc_decrypt(ciphertext.as_slice(), key, iv.as_slice());

        assert_eq!(plaintext, pkcs7_unpad(plaintext2.as_slice()));
    }

    #[test]
    fn test_aes128_ecb() {
        let plaintext =
            "Hello hello, my name is Inigo Montoya. You killed my father. Prepare to die."
                .as_bytes();

        let key = "YELLOW SUBMARINE".as_bytes();

        let ciphertext = aes128_ecb_encrypt(pkcs7_pad(plaintext, 16).as_slice(), key);
        let plaintext2 = aes128_ecb_decrypt(ciphertext.as_slice(), key);

        assert_eq!(plaintext, pkcs7_unpad(plaintext2.as_slice()));
    }
}
