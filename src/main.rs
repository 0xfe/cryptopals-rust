use base64::{engine::general_purpose, Engine};
use tracing::*;
use tracing_subscriber::FmtSubscriber;

fn ex1() {
    info!("Running: ex1");
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let decoded = hex::decode(input).unwrap();
    let encoded = general_purpose::STANDARD.encode(&decoded);
    assert_eq!(
        encoded,
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );
}

fn ex2() {
    info!("Running: ex2");
    let input = "1c0111001f010100061a024b53535009181c";
    let decoded = hex::decode(input).unwrap();
    let input2 = "686974207468652062756c6c277320657965";
    let decoded2 = hex::decode(input2).unwrap();

    let mut result = Vec::new();
    for (a, b) in decoded.iter().zip(decoded2.iter()) {
        result.push(a ^ b);
    }

    let encoded = hex::encode(result);
    assert_eq!(encoded, "746865206b696420646f6e277420706c6179");
}

fn get_expected_frequency(c: u8) -> f32 {
    const FREQ_TABLE: [f32; 26] = [
        0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, // A-F
        0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025, // G-L
        0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, // M-R
        0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150, // S-X
        0.01974, 0.00074, // Y-Z
    ];

    let c = c.to_ascii_uppercase();
    if c < 'A' as u8 || c > 'Z' as u8 {
        match c as char {
            ' ' => return 0.15,
            '\'' => return 0.01,
            ',' => return 0.01,
            '.' => return 0.01,
            '!' => return 0.01,
            '?' => return 0.01,
            _ => return 0.0001,
        }
    }

    let index = c - 'A' as u8;
    FREQ_TABLE[index as usize]
}

/// Score the text based on how closely it matches the expected frequency of letters in English.
/// The lower the score, the closer the match.
fn score_englishness(text: Vec<u8>) -> f32 {
    let len = text.len();

    // count the number of occurrences of each letter
    let mut observed_count = [0; 256];
    for c in text {
        let c = c.to_ascii_uppercase();
        observed_count[c as usize] += 1;
    }

    // Run a chi-squared test: https://en.wikipedia.org/wiki/Chi-squared_test
    //
    // The chi-squared test is used to determine whether there is a significant difference
    // between the expected frequencies and the observed frequencies of the characters.
    let mut error_score = 0.0;
    for i in 0..255 {
        let expected_count = get_expected_frequency(i) * len as f32;
        error_score +=
            (expected_count - observed_count[i as usize] as f32).powi(2) / expected_count;
    }

    error_score.sqrt()
}

fn ex3() {
    info!("Running: ex3");
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let decoded = hex::decode(input).unwrap();

    let mut scores = [0.0; 256];
    let mut min = std::f32::MAX;
    let mut min_char = 0;
    for c in 0..255 {
        let mut result = Vec::new();
        for a in decoded.iter() {
            result.push(a ^ c);
        }

        let score = score_englishness(result);
        scores[c as usize] = score;

        if score < min {
            min = score;
            min_char = c;
            debug!("New min: {} ({})", min, min_char);
        }
    }

    let mut result = Vec::new();
    for a in decoded.iter() {
        result.push(a ^ min_char);
    }

    let result = String::from_utf8(result).unwrap();
    info!("Decoded: {:?}", result);
    assert_eq!(result, "Cooking MC's like a pound of bacon");
}

fn init_logger() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

fn main() {
    init_logger();
    ex1();
    ex2();
    ex3();
}