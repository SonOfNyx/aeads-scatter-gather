//! Core AEAD cipher implementation for (X)ChaCha20Poly1305.
use ::cipher::{StreamCipher, StreamCipherSeek};
use aead::Error;
use aead::{array::Array, inout::InOutBuf};
use poly1305::{
    Poly1305,
    universal_hash::{KeyInit, UniversalHash},
};

use super::Tag;

/// Size of a ChaCha20 block in bytes
const BLOCK_SIZE: usize = 64;

/// Maximum number of blocks that can be encrypted with ChaCha20 before the
/// counter overflows.
const MAX_BLOCKS: usize = u32::MAX as usize;

#[cfg(feature = "standard")]
pub(crate) use standard::*;

#[cfg(feature = "standard")]
pub mod standard {
    use super::*;
    /// ChaCha20Poly1305 instantiated with a particular nonce
    pub(crate) struct Cipher<C>
    where
        C: StreamCipher + StreamCipherSeek,
    {
        cipher: C,
        mac: Poly1305,
    }

    impl<C> Cipher<C>
    where
        C: StreamCipher + StreamCipherSeek,
    {
        /// Instantiate the underlying cipher with a particular nonce
        pub(crate) fn new(mut cipher: C) -> Self {
            // Derive Poly1305 key from the first 32-bytes of the ChaCha20 keystream
            let mut mac_key = poly1305::Key::default();
            cipher.apply_keystream(&mut mac_key);

            let mac = Poly1305::new(&mac_key);
            #[cfg(feature = "zeroize")]
            {
                use zeroize::Zeroize;
                mac_key.zeroize();
            }

            // Set ChaCha20 counter to 1
            cipher.seek(BLOCK_SIZE as u64);

            Self { cipher, mac }
        }

        /// Encrypt the given message in-place, returning the authentication tag
        pub(crate) fn encrypt_inout_detached(
            mut self,
            associated_data: &[u8],
            mut buffer: InOutBuf<'_, '_, u8>,
        ) -> Result<Tag, Error> {
            if buffer.len() / BLOCK_SIZE >= MAX_BLOCKS {
                return Err(Error);
            }

            self.mac.update_padded(associated_data);

            // TODO(tarcieri): interleave encryption with Poly1305
            // See: <https://github.com/RustCrypto/AEADs/issues/74>
            self.cipher.apply_keystream_inout(buffer.reborrow());
            self.mac.update_padded(buffer.get_out());

            self.authenticate_lengths(associated_data, buffer.get_out())?;
            Ok(self.mac.finalize())
        }

        /// Decrypt the given message, first authenticating ciphertext integrity
        /// and returning an error if it's been tampered with.
        pub(crate) fn decrypt_inout_detached(
            mut self,
            associated_data: &[u8],
            buffer: InOutBuf<'_, '_, u8>,
            tag: &Tag,
        ) -> Result<(), Error> {
            if buffer.len() / BLOCK_SIZE >= MAX_BLOCKS {
                return Err(Error);
            }

            self.mac.update_padded(associated_data);
            self.mac.update_padded(buffer.get_in());
            self.authenticate_lengths(associated_data, buffer.get_in())?;

            // This performs a constant-time comparison using the `subtle` crate
            if self.mac.verify(tag).is_ok() {
                // TODO(tarcieri): interleave decryption with Poly1305
                // See: <https://github.com/RustCrypto/AEADs/issues/74>
                self.cipher.apply_keystream_inout(buffer);
                Ok(())
            } else {
                Err(Error)
            }
        }

        /// Authenticate the lengths of the associated data and message
        fn authenticate_lengths(
            &mut self,
            associated_data: &[u8],
            buffer: &[u8],
        ) -> Result<(), Error> {
            let associated_data_len: u64 = associated_data.len().try_into().map_err(|_| Error)?;
            let buffer_len: u64 = buffer.len().try_into().map_err(|_| Error)?;

            let mut block = Array::default();
            block[..8].copy_from_slice(&associated_data_len.to_le_bytes());
            block[8..].copy_from_slice(&buffer_len.to_le_bytes());
            self.mac.update(&[block]);

            Ok(())
        }
    }
}

#[cfg(any(feature = "streaming-one-pass", feature = "streaming-two-pass"))]
pub use streaming::*;

#[cfg(any(feature = "streaming-one-pass", feature = "streaming-two-pass"))]
pub mod streaming {
    use super::*;
    use core::marker::PhantomData;

    const MAX_PAYLOAD_LEN: u64 = MAX_BLOCKS as u64 * BLOCK_SIZE as u64;

    // Private trait to prevent external implementations of `ValidNextPhase`
    mod private {
        pub trait Locked {}
    }

    // Trait to allow two valid next phases following the AADPhase: EncryptionPhase and DecryptionPhase
    pub trait ValidNextPhase: private::Locked {}

    /// Phase for processing additional authenticated data (AAD) for tag generation
    #[derive(Debug, Clone, Copy)]
    pub struct AadPhase;

    /// Phase for processing plaintext for encryption and tag generation
    #[derive(Debug, Clone, Copy)]
    pub struct EncryptionPhase;
    impl private::Locked for EncryptionPhase {}
    impl ValidNextPhase for EncryptionPhase {}

    #[cfg(feature = "streaming-one-pass")]
    /// Phase for processing ciphertext for decryption and tag verification
    #[derive(Debug, Clone, Copy)]
    pub struct OnePassDecryptionPhase;
    #[cfg(feature = "streaming-one-pass")]
    impl private::Locked for OnePassDecryptionPhase {}
    #[cfg(feature = "streaming-one-pass")]
    impl ValidNextPhase for OnePassDecryptionPhase {}

    #[cfg(feature = "streaming-two-pass")]
    /// Phase for processing ciphertext for verification and tag verification
    #[derive(Debug, Clone, Copy)]
    pub struct VerificationPhase;
    #[cfg(feature = "streaming-two-pass")]
    impl private::Locked for VerificationPhase {}
    #[cfg(feature = "streaming-two-pass")]
    impl ValidNextPhase for VerificationPhase {}

    #[cfg(feature = "streaming-two-pass")]
    /// Phase for processing ciphertext for decryption after tag verification
    #[derive(Debug, Clone, Copy)]
    pub struct DecryptionPhase;

    /// ChaCha20Poly1305 scatter/gather style instantiated with a particular nonce
    #[derive(Debug)]
    pub struct StreamingCipher<C, State, MacType = Poly1305>
    where
        C: StreamCipher + StreamCipherSeek,
    {
        cipher: C,
        mac: MacType,
        aad_len: u64,
        payload_len: u64,
        buffer: [u8; 16],
        buffer_pos: usize,
        _state: PhantomData<State>,
    }

    impl<C, State> StreamingCipher<C, State>
    where
        C: StreamCipher + StreamCipherSeek,
    {
        // Helper function to process data in chunks of 16 bytes for Poly1305 MAC computation.
        fn process_mac(&mut self, mut data: &[u8]) -> Result<(), Error> {
            // If there's leftover data in the buffer from a previous call, it needs to be processed first.
            if self.buffer_pos > 0 {
                let space = 16 - self.buffer_pos;
                // If the incoming data is enough to fill the buffer, process it.
                // Otherwise, just fill the buffer and return.
                if data.len() >= space {
                    self.buffer[self.buffer_pos..16].copy_from_slice(&data[..space]);

                    let block = self.buffer.as_slice().try_into().map_err(|_| Error)?;
                    self.mac.update(&[block]);

                    data = &data[space..];
                    self.buffer_pos = 0;
                } else {
                    self.buffer[self.buffer_pos..self.buffer_pos + data.len()]
                        .copy_from_slice(data);
                    self.buffer_pos += data.len();
                    return Ok(());
                }
            }

            let mut offset = 0;
            while offset + 16 <= data.len() {
                let block = data[offset..offset + 16].try_into().map_err(|_| Error)?;
                self.mac.update(&[block]);

                offset += 16;
            }

            let remainder = &data[offset..];
            if !remainder.is_empty() {
                self.buffer[..remainder.len()].copy_from_slice(remainder);
                self.buffer_pos = remainder.len();
            }
            Ok(())
        }

        fn check_and_update_payload_len(&mut self, len: usize) -> Result<(), Error> {
            let new_payload_len = self.payload_len.checked_add(len as u64).ok_or(Error)?;
            if new_payload_len > MAX_PAYLOAD_LEN {
                #[cfg(feature = "zeroize")]
                {
                    use zeroize::Zeroize;
                    self.buffer.zeroize();
                    self.aad_len.zeroize();
                    self.payload_len.zeroize();
                    self.buffer_pos.zeroize();
                }
                return Err(Error);
            }
            self.payload_len = new_payload_len;
            Ok(())
        }
    }

    impl<C> StreamingCipher<C, AadPhase>
    where
        C: StreamCipher + StreamCipherSeek,
    {
        /// Creates new StreamingCipher instance
        pub fn new(mut cipher: C) -> Self {
            let mut mac_key = poly1305::Key::default();
            cipher.apply_keystream(&mut mac_key);

            let mac = Poly1305::new(&mac_key);
            #[cfg(feature = "zeroize")]
            {
                use zeroize::Zeroize;
                mac_key.zeroize();
            }

            cipher.seek(BLOCK_SIZE as u64);

            Self {
                cipher,
                mac,
                aad_len: 0,
                payload_len: 0,
                buffer: [0u8; 16],
                buffer_pos: 0,
                _state: PhantomData,
            }
        }

        /// Function to incrementally update the AAD.
        /// This function can be called multiple times with different slices of AAD data.
        /// This is step 1 of the streaming encryption/decryption process.
        /// Afterwards, the `finish_aad` function must be called to finalize the AAD processing.
        pub fn update_aad(&mut self, data: &[u8]) -> Result<(), Error> {
            self.process_mac(data)?;
            self.aad_len = self.aad_len.checked_add(data.len() as u64).ok_or(Error)?;
            Ok(())
        }

        /// Function to finalize the AAD processing.
        pub fn finish_aad<NextPhase: ValidNextPhase>(
            mut self,
        ) -> Result<StreamingCipher<C, NextPhase>, Error> {
            if self.buffer_pos > 0 {
                let remainder = &self.buffer[..self.buffer_pos];
                self.mac.update_padded(remainder);
                self.buffer_pos = 0;
            }

            Ok(StreamingCipher {
                cipher: self.cipher,
                mac: self.mac,
                aad_len: self.aad_len,
                payload_len: self.payload_len,
                buffer: self.buffer,
                buffer_pos: self.buffer_pos,
                _state: PhantomData,
            })
        }
    }

    impl<C> StreamingCipher<C, EncryptionPhase>
    where
        C: StreamCipher + StreamCipherSeek,
    {
        /// Function to incrementally update the plaintext for encryption.
        /// This function can be called multiple times with different slices of plaintext data.
        /// This is step 2 of the streaming encryption process.
        /// Afterwards, the `finalize` function must be called to finalize
        /// the plaintext processing and obtain the authentication tag.
        pub fn update_plaintext(&mut self, mut buffer: InOutBuf<'_, '_, u8>) -> Result<(), Error> {
            self.check_and_update_payload_len(buffer.len())?;

            self.cipher.apply_keystream_inout(buffer.reborrow());
            self.process_mac(buffer.get_out())?;
            Ok(())
        }

        /// Function to finalize the streaming encryption process and obtain the authentication tag.
        pub fn finalize(mut self) -> Result<Tag, Error> {
            if self.buffer_pos > 0 {
                let remainder = &self.buffer[..self.buffer_pos];
                self.mac.update_padded(remainder);
            }

            let mut block = Array::default();
            block[..8].copy_from_slice(&self.aad_len.to_le_bytes());
            block[8..].copy_from_slice(&self.payload_len.to_le_bytes());
            self.mac.update(&[block]);

            Ok(self.mac.finalize())
        }
    }

    #[cfg(feature = "streaming-one-pass")]
    impl<C> StreamingCipher<C, OnePassDecryptionPhase>
    where
        C: StreamCipher + StreamCipherSeek,
    {
        /// Function to incrementally update the ciphertext for verification and decryption.
        /// This function can be called multiple times with different slices of ciphertext data.
        /// This is step 2 of the streaming decryption process.
        /// Afterwards, the `verify_and_finalize` function must be called to finalize
        /// the processing, and verify the tag.
        ///
        /// # SECURITY WARNING: Release of Unverified Plaintext (RUP)
        /// This streaming API decrypts data **before** the Poly1305 tag is verified.
        /// This means:
        ///
        /// 1. **Do not trust, parse, or evaluate** the plaintext until
        ///    `verify_and_finalize` returns `Ok(())`.
        /// 2. **Immediately discard/zeroize** all decrypted data if
        ///    verification fails.
        pub fn update_ciphertext_unverified(
            &mut self,
            mut buffer: InOutBuf<'_, '_, u8>,
        ) -> Result<(), Error> {
            self.check_and_update_payload_len(buffer.len())?;
            self.process_mac(buffer.get_in())?;
            self.cipher.apply_keystream_inout(buffer.reborrow());
            Ok(())
        }

        /// Function to verify the authentication tag and finalize the streaming decryption process.
        pub fn verify_and_finalize(mut self, expected_tag: &Tag) -> Result<(), Error> {
            if self.buffer_pos > 0 {
                let remainder = &self.buffer[..self.buffer_pos];
                self.mac.update_padded(remainder);
            }

            let mut block = Array::default();
            block[..8].copy_from_slice(&self.aad_len.to_le_bytes());
            block[8..].copy_from_slice(&self.payload_len.to_le_bytes());
            self.mac.update(&[block]);

            if self.mac.verify(expected_tag).is_ok() {
                Ok(())
            } else {
                #[cfg(feature = "zeroize")]
                {
                    use zeroize::Zeroize;
                    self.buffer.zeroize();
                    self.aad_len.zeroize();
                    self.payload_len.zeroize();
                    self.buffer_pos.zeroize();
                }
                Err(Error)
            }
        }
    }

    #[cfg(feature = "streaming-two-pass")]
    impl<C> StreamingCipher<C, VerificationPhase>
    where
        C: StreamCipher + StreamCipherSeek,
    {
        /// Function to incrementally update the ciphertext for verification
        pub fn update_ciphertext(&mut self, data: &[u8]) -> Result<(), Error> {
            self.check_and_update_payload_len(data.len())?;
            self.process_mac(data)?;
            Ok(())
        }

        /// Function to verify the authentication tag.
        pub fn verify(
            mut self,
            expected_tag: &Tag,
        ) -> Result<StreamingCipher<C, DecryptionPhase, ()>, Error> {
            if self.buffer_pos > 0 {
                let remainder = &self.buffer[..self.buffer_pos];
                self.mac.update_padded(remainder);
            }

            let mut block = Array::default();
            block[..8].copy_from_slice(&self.aad_len.to_le_bytes());
            block[8..].copy_from_slice(&self.payload_len.to_le_bytes());
            self.mac.update(&[block]);

            if self.mac.verify(expected_tag).is_ok() {
                Ok(StreamingCipher {
                    cipher: self.cipher,
                    mac: (),
                    aad_len: self.aad_len,
                    payload_len: self.payload_len,
                    buffer: self.buffer,
                    buffer_pos: self.buffer_pos,
                    _state: PhantomData,
                })
            } else {
                #[cfg(feature = "zeroize")]
                {
                    use zeroize::Zeroize;
                    self.buffer.zeroize();
                    self.aad_len.zeroize();
                    self.payload_len.zeroize();
                    self.buffer_pos.zeroize();
                }
                Err(Error)
            }
        }
    }

    #[cfg(feature = "streaming-two-pass")]
    impl<C> StreamingCipher<C, DecryptionPhase, ()>
    where
        C: StreamCipher + StreamCipherSeek,
    {
        /// Function to incrementally update the ciphertext for decryption after tag verification.
        pub fn update_ciphertext_verified(
            &mut self,
            mut buffer: InOutBuf<'_, '_, u8>,
        ) -> Result<(), Error> {
            // Check whether the length of the supplied ciphertext in this phase exceeds the length
            // of the one supplied in the previous phase. Done by incrementally reducing the previous
            // count.
            let len = buffer.len() as u64;
            if len > self.payload_len {
                return Err(Error);
            }
            self.payload_len -= len;

            self.cipher.apply_keystream_inout(buffer.reborrow());
            Ok(())
        }

        /// Function to finalize the decryption process. Must be called to ensure the exact amount of
        /// authenticated data was processed.
        pub fn finalize(self) -> Result<(), Error> {
            if self.payload_len != 0 {
                return Err(Error);
            }
            Ok(())
        }
    }
}
