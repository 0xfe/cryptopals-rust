use crate::aes::*;
use crate::util::*;
use base64::{engine::general_purpose, Engine};
use rand::Rng;
use rand::RngCore;
use tracing::*;

fn challenge9() {
    info!("Running: challenge9");
    let input = "YELLOW SUBMARINE".as_bytes();
    let output = pkcs7_pad(input, 20);

    assert_eq!(output, "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes());
    assert_eq!(pkcs7_unpad(output.as_slice()), input);
}

fn challenge10() {
    info!("Running: challenge10");
    let data = std::fs::read_to_string("data/10.txt")
        .unwrap()
        .replace("\n", "");

    let data = general_purpose::STANDARD.decode(&data).unwrap();
    let key = "YELLOW SUBMARINE".as_bytes();

    let plaintext = aes128_cbc_decrypt(data.as_slice(), key, &[0; 16]);
    assert!(String::from_utf8(plaintext.clone())
        .unwrap()
        .starts_with("I'm back and I'm ringin' the bell"));
}

/// Pads the input with a random number of random bytes before and after, then encrypts it with
/// either ECB or CBC (randomly picking each mode) using a random key.
///
/// Returns the ciphertext and a bool indicating whether ECB was used.
fn encryption_oracle(input: &[u8]) -> (Vec<u8>, bool) {
    let mut rng = rand::thread_rng();

    // Generate a random 128-bit key.
    let mut key = [0u8; 16];
    rng.fill_bytes(&mut key);

    let mut bytes_before = vec![0u8; rng.gen_range(1..5)];
    let mut bytes_after = vec![0u8; rng.gen_range(1..5)];

    rng.fill_bytes(&mut bytes_before);
    rng.fill_bytes(&mut bytes_after);

    let padded_input = pkcs7_pad(
        [bytes_before, input.to_vec(), bytes_after]
            .concat()
            .as_slice(),
        16,
    );

    let is_ecb = rng.gen_bool(0.5);

    if is_ecb {
        debug!("Encrypting with ECB");
        (aes128_ecb_encrypt(padded_input.as_slice(), &key), true)
    } else {
        debug!("Encrypting with CBC");
        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut iv);
        (
            aes128_cbc_encrypt(padded_input.as_slice(), &key, &iv),
            false,
        )
    }
}

fn num_repeating_blocks(input: &[u8]) -> usize {
    let mut num_repeated = 0;
    for (i, chunk) in input.chunks(16).enumerate() {
        for chunk2 in input.chunks(16).skip(i + 1) {
            if chunk.eq(chunk2) {
                num_repeated += 1;
            }
        }
    }
    debug!("num_repeated: {}", num_repeated);
    num_repeated
}

fn challenge11() {
    info!("Running: challenge11");
    // Our plaintext input is a big list of repeating zeros.
    let data = vec![0; 48];

    fn is_ecb_encrypted(ciphertext: &[u8]) -> bool {
        num_repeating_blocks(ciphertext) > 0
    }

    for _ in 0..5 {
        let (ciphertext, is_ecb) = encryption_oracle(data.as_slice());
        assert_eq!(is_ecb, is_ecb_encrypted(ciphertext.as_slice()));
    }
}

pub fn run() {
    info!("Running Set 2");
    challenge9();
    challenge10();
    challenge11();
}
