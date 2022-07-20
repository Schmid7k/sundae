#![feature(portable_simd)]
#![no_std]
//#![warn(missing_docs, rust_2018_idioms)]

#[cfg(target_arch = "x86")]
use core::arch::x86 as arch;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as arch;

use aead::Payload;
use arch::{
    __m128i, _mm_loadu_si128, _mm_set_epi8, _mm_storeu_si128, _mm_xor_si128, _mm_shuffle_epi8
};

pub use aead::{self, AeadCore, AeadInPlace, Error, NewAead};
pub use cipher::Key;

use cipher::{
    consts::{U0, U16, U8},
    generic_array::{ArrayLength, GenericArray},
    BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit, KeySizeUser,
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

#[cfg(feature = "aes")]
pub type SundaeAes = Sundae<Aes128, U8>;

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
    B: BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt + KeyInit,
{
    type KeySize = B::KeySize;

    fn new(key: &Key<Self>) -> Self {
        B::new(key).into()
    }
}

impl<B, NonceSize> From<B> for Sundae<B, NonceSize>
where
    B: BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
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
    B: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
    NonceSize: ArrayLength<u8>,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        unsafe {
            let mut pt_len = buffer.len();
            let mut ad_len = associated_data.len();
            // Setting the initial value for whether ad is empty or not
            let b1: i8 = if ad_len > 0 { 0x8 } else { 0 };
            // Setting the initial value for whether pt is empty or not
            let b2: i8 = if pt_len > 0 { 0x4 } else { 0 };

            let mul2 = _mm_set_epi8(14,13,12,11,10,9,8,7,6,5,4,3,2,1,0,-1);
            let xor2 = _mm_set_epi8(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 15, -1, 15, -1, 15, -1);

            let mut block: __m128i;
            let mut v = self.bc_encrypt(_mm_set_epi8((b1 | b2) << 4,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0));
            
            let mut tag = [0u8; 16];
            _mm_storeu_si128(tag[..].as_ptr() as *mut __m128i, v);

            let mut block_start = 0;
            let mut block_end = 16;

            // Tag computing over associated data
            if ad_len > 0 {
                while ad_len > 16 {
                    block = _mm_loadu_si128(associated_data[block_start..block_end].as_ptr() as *const __m128i);
                    v = self.bc_encrypt(_mm_xor_si128(v, block));
    
                    ad_len -= 16;
                    block_start += 16;
                    block_end += 16;
                }
                block = _mm_loadu_si128(associated_data[block_start..].as_ptr() as *const __m128i);
                v = _mm_shuffle_epi8(mul2, _mm_xor_si128(v, block));
                v = self.bc_encrypt(v);
                _mm_storeu_si128(tag[..].as_ptr() as *mut __m128i, v);
            }

            block_start = 0;
            block_end = 16;

            if pt_len > 0 {
                while pt_len > 16 {
                    block = _mm_loadu_si128(buffer[block_start..block_end].as_ptr() as *const __m128i);
                    v = self.bc_encrypt(_mm_xor_si128(v, block));
    
                    pt_len -= 16;
                    block_start += 16;
                    block_end += 16;
                }
                block = _mm_loadu_si128(buffer[block_start..block_end].as_ptr() as *const __m128i);
                v = _mm_shuffle_epi8(mul2, _mm_xor_si128(v, block));
                v = self.bc_encrypt(v);
                _mm_storeu_si128(tag[..].as_ptr() as *mut __m128i, v);
            }

            block_start = 0;
            block_end = 16;
            pt_len = buffer.len();

            while pt_len > 0 {
                v = self.bc_encrypt(v);

                _mm_storeu_si128(buffer[block_start..block_end].as_ptr() as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(buffer[block_start..block_end].as_ptr() as *const __m128i), v));

                block_start += 16;
                block_end += 16;
                pt_len -= 16;
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
            let mut block_start = 0;
            let mut block_end = 16;

            let mut block: __m128i;
            let mut v = _mm_loadu_si128(tag[..].as_ptr() as *const __m128i);

            while ct_len > 0 {
                v = self.bc_encrypt(v);
                block = _mm_loadu_si128(buffer[block_start..block_end].as_ptr() as *const __m128i);
                _mm_storeu_si128(buffer[block_start..block_end].as_ptr() as *mut __m128i, _mm_xor_si128(v, block));
                
                block_start += 16;
                block_end += 16;
                ct_len -= 16;
            }

            if !buffer.is_empty() {
                let payload = Payload {
                    aad: associated_data,
                    msg: buffer
                };
                let test = self::aead::Aead::encrypt(self, nonce, payload).expect("Encryption error");
                assert!(test[test.len()-16..] == tag.to_vec());
            }

            Ok(())
        }
    }
}

impl<B, NonceSize> Sundae<B, NonceSize>
where
    B: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
    NonceSize: ArrayLength<u8>,
{
    // Encryption procedure of the internal block cipher
    #[inline]
    fn bc_encrypt(&self, _in: __m128i) -> __m128i {
        let mut tmp = u8x16::from(_in);
        self.cipher.encrypt_block(tmp.as_mut_array().into());
        tmp.into()
    }

    // Decryption procedure of the internal block cipher
    #[inline]
    fn bc_decrypt(&self, _in: __m128i) -> __m128i {
        let mut tmp = u8x16::from(_in);
        self.cipher.decrypt_block(tmp.as_mut_array().into());
        tmp.into()
    }
}