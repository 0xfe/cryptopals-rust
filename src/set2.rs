use crate::util::*;
use base64::{engine::general_purpose, Engine};
use tracing::*;

fn challenge1() {
    info!("Running: challenge1");
    let input = "YELLOW SUBMARINE".as_bytes();
    let output = pkcs7_pad(input, 20);

    assert_eq!(output, "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes());
}

fn challenge2() {
    info!("Running: challenge2");
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

pub fn run() {
    info!("Running Set 2");
    challenge1();
    challenge2();
}
