use sundae::{aead::Aead, NewAead, SundaeAes};

#[test]
fn test_encrypt() {
    let key = [0u8; 16];
    let cipher = SundaeAes::new(&key.into());

    let res = cipher.encrypt(&[0u8; 8].into(), [0u8; 128].as_ref()).expect("Encryption failed");

    println!("{:#02x?}", res);
}

#[test]
fn test_decrypt() {
    let key = [0u8; 16];
    let cipher = SundaeAes::new(&key.into());

    let enc = cipher.encrypt(&[0u8; 8].into(), [0u8; 16].as_ref()).expect("Encryption failed");

    println!("{:#02x?}", enc);

    let dec = cipher.decrypt(&[0u8; 8].into(), enc.as_ref()).expect("Decryption error");

    println!("{:#02x?}", dec);
}

#[test]
fn sanity_check() {
    let key = [0u8; 16];
    let cipher = SundaeAes::new(&key.into());

    let res = cipher.encrypt(&[0u8; 8].into(), [0u8; 128].as_ref());
    res.expect("Encryption failed");
    let res = cipher.decrypt(&[0u8; 8].into(), [0u8; 128].as_ref());
    res.expect("Decryption failed");
}
