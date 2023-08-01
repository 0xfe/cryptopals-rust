/// Returns the hamming distance between two byte slices.
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

/// Pad a byte slice to a multiple of `block_size` using PKCS#7 padding.
pub fn pkcs7_pad(input: &[u8], block_size: usize) -> Vec<u8> {
    let mut output = input.to_vec();
    let pad_size = block_size - (input.len() % block_size);
    output.append(&mut vec![pad_size as u8; pad_size]);
    output
}

/// Unpad a byte slice using PKCS#7 padding.
pub fn pkcs7_unpad(input: &[u8]) -> Vec<u8> {
    let pad_size = input[input.len() - 1] as usize;
    let mut output = input.to_vec();
    output.truncate(input.len() - pad_size);
    output
}

/// XOR two byte slices together.
pub fn xor_block(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());
    let mut output = Vec::new();
    for (a, b) in a.iter().zip(b.iter()) {
        output.push(a ^ b);
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
}
