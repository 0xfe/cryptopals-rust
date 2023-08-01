use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};

pub fn hamming(a: &[u8], b: &[u8]) -> u32 {
    assert_eq!(a.len(), b.len());
    let mut count = 0;
    for (a, b) in a.iter().zip(b.iter()) {
        let mut diff = a ^ b;
        while diff > 0 {
            count += 1;
            diff &= diff - 1;
        }
    }
    count
}

pub fn aes128_decrypt_block(block: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = aes::Aes128::new_from_slice(key).unwrap();
    let mut block = *GenericArray::from_slice(block);
    cipher.decrypt_block(&mut block);
    block.to_vec()
}

pub fn aes128_encrypt_block(block: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = aes::Aes128::new_from_slice(key).unwrap();
    let mut block = *GenericArray::from_slice(block);
    cipher.encrypt_block(&mut block);
    block.to_vec()
}

pub fn pkcs7_pad(input: &[u8], block_size: usize) -> Vec<u8> {
    let mut output = input.to_vec();
    let pad_size = block_size - (input.len() % block_size);
    output.append(&mut vec![pad_size as u8; pad_size]);
    output
}

pub fn pkcs7_unpad(input: &[u8]) -> Vec<u8> {
    let pad_size = input[input.len() - 1] as usize;
    let mut output = input.to_vec();
    output.truncate(input.len() - pad_size);
    output
}

fn xor_block(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());
    let mut output = Vec::new();
    for (a, b) in a.iter().zip(b.iter()) {
        output.push(a ^ b);
    }

    output
}

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

mod test {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_hamming() {
        let a = "this is a test".as_bytes();
        let b = "wokka wokka!!!".as_bytes();
        assert_eq!(hamming(a, b), 37);
    }

    #[test]
    fn test_pkcs7_pad_unpad() {
        let test_data = vec!["a", "ab", "abc", "yellow submarine", "yellow submarines"];
        for data in test_data {
            let data = data.as_bytes();
            assert_eq!(pkcs7_pad(data, 16).len() % 16, 0);
            assert_eq!(pkcs7_unpad(pkcs7_pad(data, 16).as_slice()), data);
        }
    }

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
}
