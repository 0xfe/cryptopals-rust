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
    assert_eq!(pkcs7_unpad(output.as_slice()).unwrap(), input);
}

fn challenge10() {
    info!("Running: challenge10");
    let data = std::fs::read_to_string("data/10.txt")
        .unwrap()
        .replace('\n', "");

    let data = general_purpose::STANDARD.decode(data).unwrap();
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
        general_purpose::STANDARD.decode(suffix).unwrap()
    };

    aes128_ecb_encrypt(
        pkcs7_pad([input, suffix.as_slice()].concat().as_slice(), 16).as_slice(),
        key,
    )
}

type OracleFn = Box<dyn Fn(&[u8], &[u8]) -> Vec<u8>>;

fn challenge12and14(oracle: OracleFn, detect_block_size: bool) {
    info!("Running: challenge12and14");
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 16];
    rng.fill_bytes(&mut key);

    let key = key.as_ref();

    if detect_block_size {
        // Detect block size.
        let mut block_size = 0;
        for i in 1..64 {
            debug!("Trying block size: {}", i);
            let first = vec![0u8; i];

            let ciphertext = oracle(
                [first.as_slice(), first.as_slice()].concat().as_slice(),
                key,
            );

            if ciphertext
                .chunks(i)
                .next()
                .unwrap()
                .eq(ciphertext.chunks(i).nth(1).unwrap())
            {
                debug!("Found block size: {}", i);
                block_size = i;
                break;
            }
        }

        assert_eq!(block_size, 16);
    }

    let mut last_ciphertext = oracle(&[], key);
    let mut offset = 0;

    // Detect offset. For challeng 12, this will be 0. For challenge 14, this
    // will be some random number depending on the random prefix.
    for i in 1..16 {
        let payload = vec![0u8; i];
        let ciphertext = oracle(payload.as_slice(), key);

        if last_ciphertext.chunks(16).next().unwrap() == ciphertext.chunks(16).next().unwrap() {
            offset = i - 1;
            debug!("Found offset: {}", offset);
            break;
        }
        last_ciphertext = ciphertext;
    }

    // We don't know how large the target payload is, so start with some high
    // multiple of 16.
    let max_len = 128 + offset;
    let mut learn_prefix = vec![65; max_len - 1]; // short 1-byte for the target char
    let mut secret = vec![];

    for i in (0..max_len).rev() {
        debug!("Cracking byte: {}", i);
        let target_ciphertext = oracle(&vec![65; i], key);

        let mut matched = false;
        for c in 0..255 {
            let payload = [learn_prefix.as_ref(), [c].as_ref()].concat();
            let ciphertext = oracle(payload.as_slice(), key);

            if ciphertext[16..max_len] == target_ciphertext[16..max_len] {
                matched = true;
                secret.push(c);
                learn_prefix = [learn_prefix[1..].to_vec(), [c].to_vec()].concat();
                debug!("Cracked: [{}]", String::from_utf8_lossy(secret.as_ref()));
                break;
            }
        }

        if !matched {
            // break;
        }
    }

    assert!(String::from_utf8_lossy(secret.as_ref()).starts_with("Rollin'"));
}

fn challenge13() {
    info!("Running: challenge13");
    fn parse_cookie(input: &str) -> HashMap<String, String> {
        let parts = input.split('&');
        parts
            .map(|part| {
                let mut parts = part.split('=');
                let key = parts.next().unwrap();
                let value = parts.next().unwrap();
                (key.to_string(), value.to_string())
            })
            .collect::<HashMap<String, String>>()
    }

    fn profile_for(email: &str) -> Vec<u8> {
        let key = "YELLOW SUBMARINE".as_bytes();
        let email = email.replace(['&', '='], "");
        aes128_ecb_encrypt(
            &pkcs7_pad(format!("email={}&uid=10&role=user", email).as_bytes(), 16),
            key,
        )
        .to_vec()
    }

    // Construct an "admin" ciphertext block to replace the last block
    let admin_ciphertext = profile_for(
        std::str::from_utf8(
            ["AAAAAAAAAAadmin".as_bytes(), &[11u8; 11]]
                .concat()
                .as_slice(),
        )
        .unwrap(),
    )
    .chunks(16)
    .nth(1)
    .unwrap()
    .to_vec();

    // Construct a ciphertext block with the role string aligned to the beginning of a 128-bit
    // block. This requires a 13 character username.
    let profile_cookie = profile_for("f.o.o@bar.com")
        .chunks(16)
        .take(2)
        .collect::<Vec<&[u8]>>()
        .concat();

    let key = "YELLOW SUBMARINE".as_bytes();
    let ciphertext = [profile_cookie.clone(), admin_ciphertext.clone()].concat();
    let plaintext = &pkcs7_unpad(&aes128_ecb_decrypt(&ciphertext, key)).unwrap();
    let plaintext = std::str::from_utf8(plaintext).unwrap();

    debug!(
        "profile_cookie.len {} admin_ciphertext.len {} ciphertext.len {}",
        profile_cookie.len(),
        admin_ciphertext.len(),
        ciphertext.len()
    );

    debug!("cookie: {:?}", parse_cookie(plaintext));
}

/// This is the same as oracle12, but with a random prefix prepended to the
/// input.
fn oracle14(input: &[u8], key: &[u8]) -> Vec<u8> {
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
        general_purpose::STANDARD.decode(suffix).unwrap()
    };

    // Prepend a random prefix to the input. Let's just use 10 bytes here -- this
    // is unknown to the attacker.
    let prefix = vec![67u8; 10];

    aes128_ecb_encrypt(
        pkcs7_pad([&prefix, input, suffix.as_slice()].concat().as_slice(), 16).as_slice(),
        key,
    )
}

fn challenge15() {
    info!("Running: challenge15");
    let string = "ICE ICE BABY\x04\x04\x04\x04";
    assert!(pkcs7_unpad(string.as_bytes()).is_ok());

    let string = "ICE ICE BABY\x05\x05\x05\x05";
    assert!(pkcs7_unpad(string.as_bytes()).is_err());

    let string = "ICE ICE BABY\x01\x02\x03\x04";
    assert!(pkcs7_unpad(string.as_bytes()).is_err());
}

fn challenge16() {
    info!("Running: challenge16");
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);

    let f1 = |input: &str| -> Vec<u8> {
        let pre = "comment1=cooking%20MCs;userdata=";
        let post = ";comment2=%20like%20a%20pound%20of%20bacon";
        let input = input.replace([';', '='], "");
        aes128_cbc_encrypt(
            pkcs7_pad(format!("{}{}{}", pre, input, post).as_bytes(), 16).as_slice(),
            &key,
            &iv,
        )
    };

    let f2 = |input: &[u8]| -> bool {
        let pt = pkcs7_unpad(&aes128_cbc_decrypt(input, &key, &iv)).unwrap();
        let pt = String::from_utf8_lossy(&pt);

        for part in pt.split(';') {
            let mut kv = part.split('=');
            if kv.next().unwrap() == "admin" {
                return true;
            }
        }
        false
    };

    // We want to construct a ciphertext block that decrypts to a block that
    // contains ";admin=true;". We can do this by XORing the target string with
    // the plaintext block that contains the user input. This will result in a
    // ciphertext block that decrypts to the target string.
    let p1 = "AAAAAAAAAAAAAAAA".as_bytes();
    let p2 = ";admin=true;ab=b".as_bytes();

    let target = p1
        .iter()
        .zip(p2.iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();

    let ct = f1("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    let target = target
        .iter()
        .zip(ct.chunks(16).nth(2).unwrap().iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();

    let ct = [
        ct.chunks(16).next().unwrap(),
        ct.chunks(16).nth(1).unwrap(),
        &target,
        ct.chunks(16).nth(3).unwrap(),
        ct.chunks(16).nth(4).unwrap(),
        ct.chunks(16).nth(5).unwrap(),
        ct.chunks(16).nth(6).unwrap(),
    ]
    .concat();

    assert!(f2(&ct));
}

pub fn run(skip_slow_challenges: bool) {
    info!("Running Set 2");
    challenge9();
    challenge10();
    challenge11();
    if !skip_slow_challenges {
        challenge12and14(Box::new(oracle12), false);
    }
    challenge13();
    if !skip_slow_challenges {
        challenge12and14(Box::new(oracle14), false);
    }
    challenge15();
    challenge16();
}
