//! The [SUNDAE][1] lightweight [Authenticated Encryption and Associated Data (AEAD)][2] cipher.
//!
//! SUNDAE made it to round 2 of the [NIST lightweight cryptography competition][3] as part of SUNDAE-GIFT.
//!
//! ## Security notes
//!
//! Although encryption and decryption passes the test vector, there is no guarantee
//! of constant-time operation.
//!
//! **USE AT YOUR OWN RISK.**
//!
//! # Usage
//! ```
//! use sundae::{SundaeAes, Nonce}; // If you don't know what block cipher to use with SUNDAE choose the pre-defined type with AES, though for smaller devices GIFT would be preferable
//! use sundae::aead::{Aead, NewAead};
//!
//! let key = b"just another key";
//! let cipher = SundaeAes::new(key.into());
//!
//! let nonce = Nonce::from_slice(b"thenonce"); // SUNDAE does not use nonces
//!
//! let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref())
//!     .expect("encryption failure!"); // NOTE: handle this error to avoid panics!
//!
//! let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
//!     .expect("decryption failure!"); // NOTE: handle this error to avoic panics!
//!
//! assert_eq!(&plaintext, b"plaintext message");
//! ```
//!
//! ## Usage with AAD
//! SUNDAE can authenticate additional data that is not encrypted alongside with the ciphertext.
//! 
//! It can also be used as a [MAC][4] algorithm if only additional data is provided without plaintext.
//! ```
//! use sundae::{SundaeAes, Nonce}; // If you don't know what block cipher to use with SUNDAE choose the pre-defined type with AES, though a lightweight block cipher like GIFT would be preferable for smaller devices
//! use sundae::aead::{Aead, NewAead, Payload};
//!
//! let key = b"just another key";
//! let cipher = SundaeAes::new(key.into());
//!
//! let nonce = Nonce::from_slice(b"thenonce"); // SUNDAE does not use nonces
//!
//! let payload = Payload {
//!     msg: &b"this will be encrypted".as_ref(),
//!     aad: &b"this will NOT be encrypted, but will be authenticated".as_ref(),
//! };
//!
//! let ciphertext = cipher.encrypt(nonce, payload)
//!     .expect("encryption failure!"); // NOTE: handle this error to avoid panics!
//!
//! let payload = Payload {
//!     msg: &ciphertext,
//!     aad: &b"this will NOT be encrypted, but will be authenticated".as_ref(),
//! };
//!
//! let plaintext = cipher.decrypt(nonce, payload)
//!     .expect("decryption failure!"); // NOTE: handle this error to avoid panics!
//!
//! assert_eq!(&plaintext, b"this will be encrypted");
//! ```
//!
//! ## In-place Usage (eliminates `alloc` requirement)
//!
//! This crate has an optional `alloc` feature which can be disabled in e.g.
//! microcontroller environments that don't have a heap.
//!
//! The [`AeadInPlace::encrypt_in_place`] and [`AeadInPlace::decrypt_in_place`]
//! methods accept any type that impls the [`aead::Buffer`] trait which
//! contains the plaintext for encryption or ciphertext for decryption.
//!
//! Note that if you enable the `heapless` feature of this crate,
//! you will receive an impl of [`aead::Buffer`] for `heapless::Vec`
//! (re-exported from the [`aead`] crate as [`aead::heapless::Vec`]),
//! which can then be passed as the `buffer` parameter to the in-place encrypt
//! and decrypt methods:
//!
//! ```
//! # #[cfg(feature = "heapless")]
//! # {
//! use sundae::{SundaeAes, Nonce}; // If you don't know what block cipher to use with SUNDAE choose the pre-defined type with AES, though a lightweight block cipher like GIFT would be preferable for smaller devices
//! use sundae::aead::{AeadInPlace, NewAead};
//! use sundae::aead::heapless::Vec;
//!
//! let key = b"just another key";
//! let cipher = SundaeAes::new(key,into());
//!
//! let nonce = Nonce::from_slice(b"thenonce"); // SUNDAE does not use nonces
//!
//! let mut buffer: Vec<u8, 128> = Vec::new(); // Buffer needs 16-bytes overhead for tag
//! buffer.extend_from_slice(b"plaintext message");
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
//! cipher.encrypt_in_place(nonce, b"", &mut buffer).expect("encryption failure!");
//!
//! // `buffer` now contains the message ciphertext
//! assert_ne!(&buffer, b"plaintext message");
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//! cipher.decrypt_in_place(nonce, b"", &mut buffer).expect("decryption failure!");
//! assert_eq!(&buffer, b"plaintext message");
//! # }
//! ```
//!
//! [1]: https://csrc.nist.gov/Projects/lightweight-cryptography/round-2-candidates
//! [2]: https://en.wikipedia.org/wiki/Authenticated_encryption
//! [3]: https://csrc.nist.gov/projects/lightweight-cryptography
//! [4]: https://en.wikipedia.org/wiki/Message_authentication_code

#![feature(portable_simd)]
#![no_std]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(target_arch = "x86")]
use core::arch::x86 as arch;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as arch;

use aead::Payload;
use arch::{
    __m128i, _mm_loadu_si128, _mm_set_epi8, _mm_shuffle_epi8, _mm_storeu_si128, _mm_xor_si128,
};

pub use aead::{self, AeadCore, AeadInPlace, Error, NewAead};
pub use cipher::Key;

use cipher::{
    consts::{U0, U16, U8},
    generic_array::{ArrayLength, GenericArray},
    BlockCipher, BlockEncrypt, BlockSizeUser, KeyInit, KeySizeUser,
};

use core::marker::PhantomData;
use core::simd::u8x16;

#[cfg(feature = "aes")]
pub use aes;

#[cfg(feature = "aes")]
use aes::Aes128;

/// SUNDAE nonces
pub type Nonce<NonceSize> = GenericArray<u8, NonceSize>;

/// SUNDAE tags
pub type Tag = GenericArray<u8, U16>;

/// SUNDAE with AES128 as underlying block cipher
#[cfg(feature = "aes")]
pub type SundaeAes = Sundae<Aes128, U8>;

/// Struct representing SUNDAE generic over the underlying block cipher
#[derive(Clone)]
pub struct Sundae<B, NonceSize> {
    cipher: B,
    nonce_size: PhantomData<NonceSize>,
}

impl<B, NonceSize> KeySizeUser for Sundae<B, NonceSize>
where
    B: KeyInit,
{
    type KeySize = B::KeySize;
}

impl<B, NonceSize> NewAead for Sundae<B, NonceSize>
where
    B: BlockSizeUser<BlockSize = U16> + BlockEncrypt + KeyInit,
{
    type KeySize = B::KeySize;

    fn new(key: &Key<Self>) -> Self {
        B::new(key).into()
    }
}

impl<B, NonceSize> From<B> for Sundae<B, NonceSize>
where
    B: BlockSizeUser<BlockSize = U16> + BlockEncrypt,
{
    fn from(cipher: B) -> Self {
        Self {
            cipher,
            nonce_size: PhantomData,
        }
    }
}

impl<B, NonceSize> AeadCore for Sundae<B, NonceSize>
where
    NonceSize: ArrayLength<u8>,
{
    type NonceSize = NonceSize;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl<B, NonceSize> AeadInPlace for Sundae<B, NonceSize>
where
    B: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt,
    NonceSize: ArrayLength<u8>,
{
    fn encrypt_in_place_detached(
        &self,
        _nonce: &Nonce<NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        unsafe {
            let mut pt_len = buffer.len();
            let ad_len = associated_data.len();
            // Setting the initial value for whether ad is empty or not
            let b1: i8 = if ad_len > 0 { 0x8 } else { 0 };
            // Setting the initial value for whether pt is empty or not
            let b2: i8 = if pt_len > 0 { 0x4 } else { 0 };
            
            let mut v = self.bc_encrypt(_mm_set_epi8(
                (b1 | b2) << 4,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ));
            let mut tag = [0u8; 16];

            
            // Tag computing over associated data
            if ad_len > 0 {
                tag = self.mac(associated_data, &mut v);
            }
            // Tag computing over plaintext
            if pt_len > 0 {
                tag = self.mac(buffer, &mut v);
            }

            if pt_len > 0 {
                let mut block_start = 0;
                let mut block_end = 16;

                let mut buf = [0u8; 16];
                // Encryption procedure for complete blocks
                while pt_len > 16 {
                    v = self.bc_encrypt(v);
    
                    _mm_storeu_si128(
                        buffer[block_start..block_end].as_ptr() as *mut __m128i,
                        _mm_xor_si128(
                            _mm_loadu_si128(buffer[block_start..block_end].as_ptr() as *const __m128i),
                            v,
                        ),
                    );
    
                    block_start += 16;
                    block_end += 16;
                    pt_len -= 16;
                }
    
                // Encryption for last (maybe partial) block
                v = self.bc_encrypt(v);
    
                buf[..pt_len].copy_from_slice(&buffer[block_start..]);
    
                let tmp = u8x16::from(_mm_xor_si128(_mm_loadu_si128(buf.as_ptr() as *const __m128i), v));
                buffer[block_start..].copy_from_slice(&tmp.as_array()[..pt_len]);
            }

            Ok(tag.into())
        }
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &aead::Tag<Self>,
    ) -> Result<(), Error> {
        unsafe {
            let mut ct_len = buffer.len();

            if ct_len > 0 {
                let mut block_start = 0;
                let mut block_end = 16;

                let mut buf = [0u8; 16];
                let mut block: __m128i;
                let mut v = _mm_loadu_si128(tag[..].as_ptr() as *const __m128i);

                // Decryption procedure for complete blocks
                while ct_len > 16 {
                    v = self.bc_encrypt(v);
                    block = _mm_loadu_si128(buffer[block_start..block_end].as_ptr() as *const __m128i);
                    _mm_storeu_si128(
                        buffer[block_start..block_end].as_ptr() as *mut __m128i,
                        _mm_xor_si128(v, block),
                    );
    
                    block_start += 16;
                    block_end += 16;
                    ct_len -= 16;
                }

                // Decryption for last (maybe partial) block
                v = self.bc_encrypt(v);
                buf[..ct_len].copy_from_slice(&buffer[block_start..]);
                let tmp = u8x16::from(_mm_xor_si128(v, _mm_loadu_si128(buf.as_ptr() as *const __m128i)));
                buffer[block_start..].copy_from_slice(&tmp.as_array()[..ct_len]);
            }
            

            // Tag verification
            let payload = Payload {
                aad: associated_data,
                msg: buffer,
            };
            let test = self::aead::Aead::encrypt(self, nonce, payload).expect("Encryption error");
            assert!(test[test.len() - 16..] == tag.to_vec());

            Ok(())
        }
    }
}

impl<B, NonceSize> Sundae<B, NonceSize>
where
    B: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt,
    NonceSize: ArrayLength<u8>,
{
    #[inline]
    fn mac(&self, buffer: &[u8], v: &mut __m128i) -> [u8; 16] {
        unsafe {
            let tag = [0u8; 16];
            let mut buf = [0u8; 16];
            let mut block: __m128i;
            let mul2 = _mm_set_epi8(14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, -1);
            let xor2 = _mm_set_epi8(
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 15, -1, 15, -1, 15, -1,
            );

            let mut block_start = 0;
            let mut block_end = 16;
            let mut len = buffer.len();

            // Tag computing over associated data
            while len > 16 {
                block = _mm_loadu_si128(
                    buffer[block_start..block_end].as_ptr() as *const __m128i
                );
                *v = self.bc_encrypt(_mm_xor_si128(*v, block));

                len -= 16;
                block_start += 16;
                block_end += 16;
            }
            // Copy remaining bytes from associated data
            buf[..len].copy_from_slice(&buffer[block_start..]);
            
            // If remaining block is incomplete pad it
            if len < 16 {
                buf[len] = 0x80;
            }

            block = _mm_xor_si128(*v, _mm_loadu_si128(buf.as_ptr() as *const __m128i));
            *v = _mm_xor_si128(_mm_shuffle_epi8(block, mul2), _mm_shuffle_epi8(block, xor2));
            *v = self.bc_encrypt(*v);
            _mm_storeu_si128(tag.as_ptr() as *mut __m128i, *v);

            tag
        }
    }

    // Encryption procedure of the internal block cipher
    #[inline]
    fn bc_encrypt(&self, _in: __m128i) -> __m128i {
        let mut tmp = u8x16::from(_in);
        self.cipher.encrypt_block(tmp.as_mut_array().into());
        tmp.into()
    }
}
