use aead::Payload;
use sundae::{aead::Aead, NewAead, SundaeAes};

#[test]
fn test_encrypt() {
    let key = [0u8; 16];
    let cipher = SundaeAes::new(&key.into());

    let res = cipher
        .encrypt(&[0u8; 8].into(), [0u8; 16].as_ref())
        .expect("Encryption failed");

    println!("{:#02x?}", res);
}

#[test]
fn test_ad() {
    let key = [0u8; 16];
    let cipher = SundaeAes::new(&key.into());

    let payload = Payload {
        aad: &[0u8; 16],
        msg: &[0u8; 0],
    };

    let enc = cipher
        .encrypt(&[0u8; 8].into(), payload)
        .expect("Encryption failed");

    println!("{:#02x?}", enc);

    let payload = Payload {
        aad: &[0u8; 16],
        msg: &enc,
    };

    let dec = cipher.decrypt(&[0u8; 8].into(), payload).expect("Decryption failed");

    println!("{:#02x?}", dec);
}

#[test]
fn test_decrypt() {
    let key = [0u8; 16];
    let cipher = SundaeAes::new(&key.into());

    let enc = cipher
        .encrypt(&[0u8; 8].into(), [0u8; 16].as_ref())
        .expect("Encryption failed");

    println!("{:#02x?}", enc);

    let dec = cipher
        .decrypt(&[0u8; 8].into(), enc.as_ref())
        .expect("Decryption error");

    println!("{:#02x?}", dec);

    assert_eq!([0u8; 16], dec.as_ref());
}

#[test]
fn pt_and_ad() {
    let key = [0u8; 16];
    let cipher = SundaeAes::new(&key.into());

    let payload = Payload {
        aad: &[0u8; 16],
        msg: &[1u8; 64],
    };

    let enc = cipher
        .encrypt(&[0u8; 8].into(), payload)
        .expect("Encryption failed");

    println!("{:#02x?}", enc);

    let payload = Payload {
        aad: &[0u8; 16],
        msg: &enc,
    };

    let dec = cipher.decrypt(&[0u8; 8].into(), payload).expect("Decryption failed");

    println!("{:#02x?}", dec);
}

#[test]
fn sanity_check() {
    let key = [0u8; 16];
    let cipher = SundaeAes::new(&key.into());

    let res = cipher
        .encrypt(&[0u8; 8].into(), [0u8; 128].as_ref())
        .expect("Encryption failure");
    cipher
        .decrypt(&[0u8; 8].into(), res.as_ref())
        .expect("Decryption failure");
}
