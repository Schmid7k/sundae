use aead::Payload;
use camellia::Camellia128;
use cipher::consts::U8;
use sundae::{
    aead::{Aead, KeyInit},
    Nonce, Sundae, SundaeAes,
};

#[test]
fn camellia_test() {
    let key = b"just another key";
    let nonce = Nonce::from_slice(b"thenonce");

    let camellia = Camellia128::new(key.into());

    let cipher: Sundae<Camellia128, U8> = Sundae::from(camellia);

    let payload = Payload {
        msg: b"this will be encrypted",
        aad: b"this will NOT be encrypted, but will be authenticated",
    };

    let ciphertext = cipher.encrypt(nonce, payload).expect("encryption failure!");

    let payload = Payload {
        msg: &ciphertext,
        aad: b"this will NOT be encrypted, but will be authenticated",
    };

    let plaintext = cipher.decrypt(nonce, payload).expect("decryption failure!");

    assert_eq!(&plaintext, b"this will be encrypted");
}

#[test]
fn extensive_test() {
    let keys = [
        [0u8; 16],
        [
            0x2, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x3,
        ],
    ];
    let nonces = [[0u8; 8], [0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8]];
    let ad = [
    "",
    "a",
    "ab",
    "0123456789abcde",
    "0123456789abcdef", // 16 bytes
    "0123456789abcdefg",
    "0123456789abcdef0123456789abcde",
    "0123456789abcdef0123456789abcdef", // 32 bytes
    "0123456789abcdef0123456789abcdefg", // 33 bytes
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde", // 63 bytes
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // 64 bytes
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefg", // 65 bytes
    // 127 bytes
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
    // 128 bytes
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    // 129 bytes
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefi",
    // 255 bytes
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
    // 256 bytes
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    // 257 bytes
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefx",
    // 512 bytes
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
];
    let plaintexts = [
        "",
		"a",
		"ab",
		"0123456789abcde",
		"0123456789abcdef", // 16 bytes
		"0123456789abcdef0",
		"0123456789abcdef0123456789abcde",
		"0123456789abcdef0123456789abcdef", // 32 bytes
		"0123456789abcdef0123456789abcdef0", // 33 bytes
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde", // 63 bytes
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // 64 bytes
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", // 65 bytes
		// 127 bytes
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		// 128 bytes
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		// 129 bytes
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefo",
		// 255 bytes
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		// 256 bytes
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		// 257 bytes
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
		// 512 bytes
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		// 2032 bytes = 127 blocks
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        // 2048 bytes = 128 blocks
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ];

    for (n, nonce) in nonces.iter().enumerate() {
        for (k, key) in keys.iter().enumerate() {
            let cipher = SundaeAes::new(key.into());
            for ad in ad.iter() {
                for p in plaintexts.iter().map(|s| s.as_bytes()) {
                    let payload = Payload {
                        msg: p,
                        aad: ad.as_bytes(),
                    };
                    let size = p.len();
                    println!("Verifying n={}, k={}, a={}, p={}", n, k, ad.len(), size);

                    println!("E+D ");
                    println!("adlen={}", ad.len());
                    println!("len={}", p.len());
                    let c = cipher.encrypt(nonce.into(), payload).expect("");
                    println!("clen={}", c.len());
                    let payload = Payload {
                        msg: &c,
                        aad: ad.as_bytes(),
                    };
                    let m = cipher.decrypt(nonce.into(), payload).expect("");

                    assert!(m == p);
                }
            }
        }
    }

    println!(
        "All {} combinations passed.",
        nonces.len() * keys.len() * ad.len() * plaintexts.len()
    );
}

#[test]
#[should_panic]
fn tag_test() {
    let key = [0u8; 16];
    let nonce = [0u8; 8];
    let m = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0";

    let cipher = SundaeAes::new(&key.into());
    let mut c = cipher.encrypt(&nonce.into(), m.as_bytes()).expect("");

    println!("{:#02x?}", c);

    c[m.len() + 15] = 0x17;

    println!("{:#02x?}", c);

    cipher.decrypt(&nonce.into(), c.as_ref()).expect("");
}
