use std::collections::HashMap;

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
fn oracle11(input: &[u8], key: Option<&[u8]>) -> (Vec<u8>, bool) {
    let mut rng = rand::thread_rng();

    // Generate a random 128-bit key.
    let key = match key {
        Some(key) => key.to_vec(),
        None => {
            let mut key = [0u8; 16];
            rng.fill_bytes(&mut key);
            key.to_vec()
        }
    };

    // Generate a random number of random bytes to pad the input with.
    let mut bytes_before = vec![0u8; rng.gen_range(1..5)];
    let mut bytes_after = vec![0u8; rng.gen_range(1..5)];

    // Fill the random bytes with random data.
    rng.fill_bytes(&mut bytes_before);
    rng.fill_bytes(&mut bytes_after);

    // Pad the input with the random bytes, then pad the result to a multiple of 16 bytes.
    let padded_input = pkcs7_pad(
        [bytes_before, input.to_vec(), bytes_after]
            .concat()
            .as_slice(),
        16,
    );

    // Randomly pick whether to use ECB or CBC.
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

/// Returns the number of blocks that are repeated in the input. This is a good heuristic for
/// whether the input was encrypted with ECB.
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
    fn is_ecb_encrypted(ciphertext: &[u8]) -> bool {
        num_repeating_blocks(ciphertext) > 0
    }

    info!("Running: challenge11");

    // Our plaintext input is a big list of repeating zeros.
    let data = vec![0; 48];

    for _ in 0..5 {
        let (ciphertext, is_ecb) = oracle11(data.as_slice(), None);
        assert_eq!(is_ecb, is_ecb_encrypted(ciphertext.as_slice()));
    }
}

fn oracle12(input: &[u8], key: &[u8]) -> Vec<u8> {
    let suffix = {
        let suffix = r"
    Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK
    "
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join("");
        general_purpose::STANDARD.decode(&suffix).unwrap()
    };

    aes128_ecb_encrypt(
        pkcs7_pad([input, suffix.as_slice()].concat().as_slice(), 16).as_slice(),
        key,
    )
}

fn challenge12() {
    info!("Running: challenge12");
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 16];
    rng.fill_bytes(&mut key);

    let key = key.as_ref();

    // Detect block size.
    let mut block_size = 0;
    for i in 1..64 {
        debug!("Trying block size: {}", i);
        let first = vec![0u8; i];

        let ciphertext = oracle12(
            [first.as_slice(), first.as_slice()].concat().as_slice(),
            key,
        );

        if ciphertext
            .chunks(i)
            .nth(0)
            .unwrap()
            .eq(ciphertext.chunks(i).nth(1).unwrap())
        {
            debug!("Found block size: {}", i);
            block_size = i;
            break;
        }
    }

    assert_eq!(block_size, 16);

    fn create_map(prefix: &[u8], key: &[u8]) -> HashMap<Vec<u8>, u8> {
        let mut crack_map = HashMap::new();
        for c in 0..255 {
            let payload = [prefix, [c].as_ref()].concat();
            let ciphertext = oracle12(payload.as_slice(), key);
            crack_map.insert((ciphertext[0..prefix.len() + 1]).to_vec(), c);
        }
        crack_map
    }

    // Start with a high multiple of 16 and subtract 1.
    let max_len = 127;
    let mut prefix = vec![0u8; max_len];
    let mut learn_prefix = prefix.clone();
    let mut secret = vec![];

    loop {
        let crack_map = create_map(learn_prefix.as_slice(), key);
        let ciphertext = oracle12(prefix.as_slice(), key);

        if let Some(c) = crack_map.get(ciphertext[0..learn_prefix.len() + 1].to_vec().as_slice()) {
            secret.push(*c);
            debug!("Cracked: {}", String::from_utf8_lossy(secret.as_ref()));

            // We're done here.
            if prefix.is_empty() {
                break;
            }

            prefix = prefix[1..].to_vec();
            learn_prefix = [learn_prefix[1..].to_vec(), [*c].to_vec()].concat();
        } else {
            // Too high, decrement prefix and try again.
            if prefix.is_empty() {
                break;
            }
            prefix = prefix[1..].to_vec();
            learn_prefix = prefix.clone();
        }
    }

    assert!(String::from_utf8_lossy(secret.as_ref()).starts_with("Rollin'"));
}

pub fn run() {
    info!("Running Set 2");
    challenge9();
    challenge10();
    challenge11();
    challenge12();
}