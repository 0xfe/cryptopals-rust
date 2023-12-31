use base64::{engine::general_purpose, Engine};
use tracing::*;

use crate::aes::*;
use crate::util::*;

fn challenge1() {
    info!("Running: challenge1");
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let decoded = hex::decode(input).unwrap();
    let encoded = general_purpose::STANDARD.encode(decoded);
    assert_eq!(
        encoded,
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );
}

fn challenge2() {
    info!("Running: challenge2");
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
    let c = c.to_ascii_uppercase();
    if c.is_ascii_uppercase() {
        const FREQ_TABLE: [f32; 26] = [
            0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, // A-F
            0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025, // G-L
            0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, // M-R
            0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150, // S-X
            0.01974, 0.00074, // Y-Z
        ];

        let index = c - b'A';
        return FREQ_TABLE[index as usize];
    }

    match c as char {
        ' ' => 0.15,
        '\'' => 0.01,
        ',' => 0.01,
        '.' => 0.01,
        '!' => 0.01,
        '?' => 0.01,
        _ => 0.0001,
    }
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

fn solve_single_char_xor(input: Vec<u8>) -> (f32, u8, String) {
    let mut scores = [0.0; 256];
    let mut min = std::f32::MAX;
    let mut min_char = 0;
    for c in 0..255 {
        let mut result = Vec::new();
        for a in input.iter() {
            result.push(a ^ c);
        }

        let score = score_englishness(result);
        scores[c as usize] = score;

        if score < min {
            min = score;
            min_char = c;
        }
    }

    let mut result = Vec::new();
    for a in input.iter() {
        result.push(a ^ min_char);
    }

    let result = unsafe { String::from_utf8_unchecked(result) };
    (min, min_char, result)
}

fn challenge3() {
    info!("Running: challenge3");
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let (score, _, result) = solve_single_char_xor(hex::decode(input).unwrap());

    info!("Score: {}, Result: {:?}", score, result);
    assert_eq!(result, "Cooking MC's like a pound of bacon");
}

fn challenge4() {
    info!("Running: challenge4");

    let data = std::fs::read_to_string("data/4.txt").unwrap();
    let lines = data.split('\n');

    let mut min = std::f32::MAX;
    let mut min_result = String::new();
    for line in lines {
        let (score, _, result) = solve_single_char_xor(hex::decode(line).unwrap());
        if score < min {
            min = score;
            min_result = result;
        }
    }

    debug!("Score: {}, Result: {:?}", min, min_result);
    assert_eq!(min_result, "Now that the party is jumping\n");
}

fn crypt_xor(input: &str, key: &str) -> Vec<u8> {
    let mut result = Vec::new();
    for (i, a) in input.bytes().enumerate() {
        let key_char = key.chars().nth(i % key.len()).unwrap();
        result.push(a ^ key_char as u8);
    }

    result
}

fn challenge5() {
    info!("Running: challenge5");

    let input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let output = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    let key = "ICE";

    let result = crypt_xor(input, key);

    assert_eq!(hex::encode(result), output);
}

fn challenge6() {
    info!("Running: challenge6");

    // Read data from file, remove newlines, and decode from base64
    let data = std::fs::read_to_string("data/6.txt")
        .unwrap()
        .split('\n')
        .collect::<Vec<_>>()
        .join("");

    let data = general_purpose::STANDARD.decode(&data).unwrap();

    let mut keysize_distances = vec![];

    // For each keysize, take the first four chunks of that size and compute the average
    // hamming distance between them.
    for keysize in 2..40 {
        let first = data.chunks(keysize).next().unwrap();
        let second = data.chunks(keysize).nth(1).unwrap();
        let third = data.chunks(keysize).nth(2).unwrap();
        let fourth = data.chunks(keysize).nth(3).unwrap();

        let distance1 = hamming(first, second) as f32 / keysize as f32;
        let distance2 = hamming(third, fourth) as f32 / keysize as f32;
        keysize_distances.push((keysize, (distance1 + distance2) / 2.0));
    }

    // Sort the keysizes by distance (smallest to largest)
    keysize_distances.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

    let mut min_score = std::f32::MAX;
    let mut min_key = String::new();
    let mut min_result = vec![];

    for (keysize, _) in keysize_distances.iter().take(10) {
        let chunks = data.chunks(*keysize).collect::<Vec<&[u8]>>();

        let mut result_set = vec![];
        for i in 0..*keysize {
            let column = chunks
                .iter()
                .map(|c| *c.get(i).unwrap_or(&0))
                .collect::<Vec<u8>>();

            let (_, key_char, _) = solve_single_char_xor(column);
            result_set.push(key_char);
        }

        let key = unsafe { String::from_utf8_unchecked(result_set.clone()) };
        let result = crypt_xor(std::str::from_utf8(&data).unwrap(), &key);

        let score = score_englishness(result.clone());
        if score < min_score {
            min_score = score;
            min_key = key;
            min_result = result;
        }
    }

    debug!("Result: {:?}", unsafe {
        String::from_utf8_unchecked(min_result)
    });

    assert_eq!(min_key, "Terminator X: Bring the noise".to_string());
}

fn challenge7() {
    info!("Running: challenge7");
    // Read data from file, remove newlines, and decode from base64.
    let data = {
        let data = std::fs::read_to_string("data/7.txt").unwrap();
        general_purpose::STANDARD
            .decode(data.replace('\n', ""))
            .unwrap()
    };

    let key = "YELLOW SUBMARINE".as_bytes();
    let plaintext = String::from_utf8(aes128_ecb_decrypt(data.as_slice(), key)).unwrap();

    debug!("Decrypted:\n{}", plaintext);
    assert!(plaintext.starts_with("I'm back and I'm ringin' the bell"))
}

fn challenge8() {
    info!("Running: challenge8");

    // Read data from file, split up lines, and decode each line from hex.
    let data = std::fs::read_to_string("data/8.txt")
        .unwrap()
        .lines()
        .map(|lines| hex::decode(lines).unwrap())
        .collect::<Vec<_>>();

    // Find the line with the lowest average hamming distance between chunks.
    let mut min_score = std::f32::MAX;
    let mut best_line = 0;
    for (i, line) in data.iter().enumerate() {
        let mut score = 0.0;

        // For each chunk, aggregate the hamming distance between it and every other chunk.
        for (j, chunk) in line.chunks(16).enumerate() {
            for (k, chunk2) in line.chunks(16).enumerate() {
                if j == k {
                    continue;
                }

                score += hamming(chunk, chunk2) as f32 / 16.0;
            }
        }

        if score < min_score {
            min_score = score;
            best_line = i;
        }
    }

    assert_eq!(best_line, 132);
}

pub fn run() {
    info!("Running Set 1");
    challenge1();
    challenge2();
    challenge3();
    challenge4();
    challenge5();
    challenge6();
    challenge7();
    challenge8();
}
