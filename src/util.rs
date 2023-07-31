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

mod test {
    use super::*;

    #[test]
    fn test_hamming() {
        let a = "this is a test".as_bytes();
        let b = "wokka wokka!!!".as_bytes();
        assert_eq!(hamming(a, b), 37);
    }
}
