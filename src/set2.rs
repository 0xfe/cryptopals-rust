use tracing::*;

fn pkcs7_pad(input: &[u8], block_size: usize) -> Vec<u8> {
    let mut output = input.to_vec();
    let pad_size = (block_size as f32
        % (input.len() as f32
            - (block_size as f32 * (input.len() as f32 / block_size as f32).floor())))
        as usize;

    output.append(&mut vec![pad_size as u8; pad_size]);
    output
}

fn challenge1() {
    info!("Running: challenge1");
    let input = "YELLOW SUBMARINE".as_bytes();
    let output = pkcs7_pad(input, 20);

    assert_eq!(output, "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes());
}

pub fn run() {
    info!("Running Set 2");
    challenge1();
}
