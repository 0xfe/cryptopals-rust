use crate::aes;
use crate::aes::*;
use crate::util::*;
use rand::RngCore;
use tracing::*;

fn challenge49() {
    info!("Challenge 49");
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 16];
    rng.fill_bytes(&mut key);

    let sign_message = |from: &str, to: &str, amount: u64, iv: &[u8]| -> String {
        let message = format!("from={}&to={}&amount={}", from, to, amount);
        format!(
            "{}{}{}",
            hex::encode(&message),
            hex::encode(iv),
            hex::encode(cbc_mac(&pkcs7_pad(message.as_bytes(), 16), &key, &iv))
        )
    };

    let verify_message = |message: &str| {
        let message = hex::decode(message).unwrap();
        let mac = message[message.len() - 16..].to_vec();
        let iv = message[message.len() - 32..message.len() - 16].to_vec();
        let message = pkcs7_pad(&message[..message.len() - 32], 16);

        debug!(
            "message: {:?} mac: {} expected_mac: {}",
            String::from_utf8_lossy(&message),
            hex::encode(&mac),
            hex::encode(&cbc_mac(&message, &key, &iv))
        );
        mac == cbc_mac(&message, &key, &iv)
    };

    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut iv);
    assert!(verify_message(
        sign_message("foo", "bar", 100, &iv).as_str()
    ));

    // My account: 123456
    // Victim account: 666666

    // Sign a transfer message of 1m spacebucks with my account as the source.
    let signed_message =
        hex::decode(sign_message("123456", "123456", 1000000, &[0u8; 16])).unwrap();
    let mac1 = &signed_message[signed_message.len() - 16..];

    // Generate an IV that produces the same MAC for a transfer from the victim's account.
    let target1 = "from=123456&to=1";
    let target2 = "from=666666&to=1";
    let iv = target1
        .as_bytes()
        .iter()
        .zip(target2.as_bytes())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();

    // Reconstruct a new signed message using the victim account and the calculated IV, keeping
    // the original MAC.
    let signed_message2 = format!(
        "{}{}{}",
        hex::encode("from=666666&to=123456&amount=1000000"),
        hex::encode(&iv),
        hex::encode(mac1)
    );

    // Verify that the new message is accepted.
    assert!(verify_message(signed_message2.as_str()));
}

fn challenge50() {
    info!("Challenge 50");

    let pt = "alert('MZA who was that?');\n".as_bytes();
    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = &[0u8; 16];

    let target_pt = "alert('Ayo, the Wu is back!');\n".as_bytes();
    let target_mac = hex::decode("296b8d7cb78a243dda4d0a61d33bbdd1").unwrap();

    assert_eq!(cbc_mac(&pkcs7_pad(pt, 16), key, iv), target_mac);

    let target_last_ct = aes128_cbc_decrypt(&pkcs7_pad(pt, 16).chunks(16).last().unwrap(), key, iv);

    dbg!(target_pt.len(), key.len());
}

pub fn run() {
    info!("Running set 7");
    challenge49();
    challenge50();
}
