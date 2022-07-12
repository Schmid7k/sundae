#![feature(portable_simd)]
#![no_std]
//#![warn(missing_docs, rust_2018_idioms)]

#[cfg(target_arch = "x86")]
use core::arch::x86 as arch;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as arch;

use arch::{
    __m128i, _mm_loadu_si128, _mm_set_epi64x, _mm_setzero_si128, _mm_storeu_si128, _mm_xor_si128,
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
        let b1 = if associated_data.len() > 0 { 1 } else { 0 };
        let b2 = if buffer.len() > 0 { 1 } else { 0 };
        let mut buf = [0u8; 16];
        buf[0] = b1;
        buf[1] = b2;

        let mut tag = self.bc_encrypt(buf);

        if associated_data.len() > 0 {
            let mut remaining = associated_data.len();
            let mut block_start = 0;
            let mut block_end = 16;

            while remaining > 16 {
                buf = self.bc_encrypt(xor_block(&buf, &associated_data[block_start..block_end]));

                remaining -= 16;
                block_start += 16;
                block_end += 16;
            }

            let x = if associated_data[block_start..].len() < 16 {
                2
            } else {
                4
            };

            // V <- E(X x (V xor pad(A[l_a])))
            //buf = self.bc_encrypt(in)
        }

        Ok(tag.into())
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
    fn bc_encrypt(&self, _in: [u8; 16]) -> [u8; 16] {
        let mut tmp = GenericArray::from(_in);
        self.cipher.encrypt_block(&mut tmp);
        return tmp.into();
    }

    fn bc_decrypt(&self, _in: [u8; 16]) -> [u8; 16] {
        let mut tmp = GenericArray::from(_in);
        self.cipher.decrypt_block(&mut tmp);
        return tmp.into();
    }
}

fn xor_block(a: &[u8], b: &[u8]) -> [u8; 16] {
    let mut res = [0u8; 16];
    for i in 0..16 {
        res[i] = a[i] ^ b[i];
    }

    res
}
