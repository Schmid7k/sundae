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

///Res: [0xc8,0xca,0x46,0x5f,0x52,0xec,0x53,0x4a,0xd6,0xa0,0xb2,0x32,0xb3,0xa7,0x81,0x2c]
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

///Res: [0xeb,0x3a,0xe7,0x8c,0x1c,0xbe,0x1,0xb4,0x15,0x9b,0x91,0x3e,0xcb,0x9c,0xa2,0x99,0x3f,0x84,0x5,0x9b,0x39,0x22,0x56,0x4d,0xdf,0x84,0xc8,0x2b,0x3e,0x70,0xc2,0xb5]
#[test]
fn pt_and_ad() {
    let key = [0u8; 16];
    let cipher = SundaeAes::new(&key.into());

    let payload = Payload {
        aad: &[0u8; 16],
        msg: &[1u8; 16],
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
