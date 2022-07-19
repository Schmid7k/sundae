#![feature(portable_simd)]
#![no_std]
//#![warn(missing_docs, rust_2018_idioms)]

#[cfg(target_arch = "x86")]
use core::arch::x86 as arch;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as arch;

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
            let mut block: __m128i;
            let mut lastblock = self.bc_encrypt(_mm_set_epi8(0x40,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0));
            let mul2 = _mm_set_epi8(14,13,12,11,10,9,8,7,6,5,4,3,2,1,0,15);
            let xor2 = _mm_set_epi8(15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15);

            let mut tag = [0u8;16];

            let mut block_start = 0;
            let mut block_end = 16;
            let mut len = buffer.len();

            while len > 16 {
                block = _mm_xor_si128(_mm_loadu_si128(buffer[block_start..block_end].as_ptr() as *const __m128i), lastblock);

                self.bc_encrypt(block);

                lastblock = block;

                len -= 16;
                block_start += 16;
                block_end += 16;
            }

            block = _mm_xor_si128(_mm_loadu_si128(buffer[block_start..block_end].as_ptr() as *mut __m128i), lastblock);
            block_start += 16;
            block_end += 16;
            len -= 16;

            block = _mm_xor_si128(_mm_shuffle_epi8(block, mul2), _mm_shuffle_epi8(block, xor2));

            self.bc_encrypt(block);

            lastblock = block;

            _mm_storeu_si128(tag[..].as_ptr() as *mut __m128i, lastblock);

            block_start = 0;
            block_end = 16;
            len = buffer.len();

            while len > 0 {
                self.bc_encrypt(block);

                _mm_storeu_si128(buffer[block_start..block_end].as_ptr() as *mut __m128i, _mm_xor_si128(_mm_loadu_si128(buffer[block_start..block_end].as_ptr() as *const __m128i), block));

                block_start += 16;
                block_end += 16;
                len -= 16;
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
        Ok(())
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