//! Cryptographic primitive traits.

use crate::Result;
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Key Encapsulation Mechanism (KEM) trait.
///
/// This trait defines the interface for key encapsulation mechanisms
/// as specified in NIST post-quantum cryptography standards.
///
/// # Type Parameters
///
/// Implementations should define associated types for keys and ciphertext,
/// ensuring proper zeroization of sensitive material.
///
/// # Example
///
/// ```ignore
/// use kylix_core::Kem;
///
/// let (dk, ek) = MyKem::keygen(&mut rng)?;
/// let (ct, ss_sender) = MyKem::encaps(&ek, &mut rng)?;
/// let ss_receiver = MyKem::decaps(&dk, &ct)?;
/// ```
pub trait Kem {
    /// Decapsulation key (private key).
    type DecapsulationKey: Zeroize + ZeroizeOnDrop;

    /// Encapsulation key (public key).
    type EncapsulationKey: Clone;

    /// Ciphertext produced by encapsulation.
    type Ciphertext: Clone;

    /// Shared secret produced by encapsulation/decapsulation.
    type SharedSecret: Zeroize + ZeroizeOnDrop + AsRef<[u8]>;

    /// Size of the decapsulation key in bytes.
    const DECAPSULATION_KEY_SIZE: usize;

    /// Size of the encapsulation key in bytes.
    const ENCAPSULATION_KEY_SIZE: usize;

    /// Size of the ciphertext in bytes.
    const CIPHERTEXT_SIZE: usize;

    /// Size of the shared secret in bytes.
    const SHARED_SECRET_SIZE: usize;

    /// Generate a new key pair.
    ///
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator.
    ///
    /// # Returns
    ///
    /// A tuple of (decapsulation_key, encapsulation_key).
    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey)>;

    /// Encapsulate a shared secret using the encapsulation key.
    ///
    /// # Arguments
    ///
    /// * `ek` - The encapsulation (public) key.
    /// * `rng` - A cryptographically secure random number generator.
    ///
    /// # Returns
    ///
    /// A tuple of (ciphertext, shared_secret).
    fn encaps(
        ek: &Self::EncapsulationKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret)>;

    /// Decapsulate a shared secret using the decapsulation key.
    ///
    /// # Arguments
    ///
    /// * `dk` - The decapsulation (private) key.
    /// * `ct` - The ciphertext to decapsulate.
    ///
    /// # Returns
    ///
    /// The shared secret.
    ///
    /// # Security
    ///
    /// Implementations MUST use implicit rejection to prevent
    /// chosen-ciphertext attacks. Invalid ciphertexts should
    /// produce a pseudorandom shared secret derived from the
    /// private key and ciphertext.
    fn decaps(dk: &Self::DecapsulationKey, ct: &Self::Ciphertext) -> Result<Self::SharedSecret>;
}

/// Digital signature trait.
///
/// This trait defines the interface for digital signature schemes
/// as specified in NIST post-quantum cryptography standards.
///
/// # Example
///
/// ```ignore
/// use kylix_core::Signer;
///
/// let (sk, pk) = MySigner::keygen(&mut rng)?;
/// let sig = MySigner::sign(&sk, message)?;
/// MySigner::verify(&pk, message, &sig)?;
/// ```
pub trait Signer {
    /// Signing key (private key).
    type SigningKey: Zeroize + ZeroizeOnDrop;

    /// Verification key (public key).
    type VerificationKey: Clone;

    /// Signature produced by signing.
    type Signature: Clone;

    /// Size of the signing key in bytes.
    const SIGNING_KEY_SIZE: usize;

    /// Size of the verification key in bytes.
    const VERIFICATION_KEY_SIZE: usize;

    /// Maximum size of the signature in bytes.
    const SIGNATURE_SIZE: usize;

    /// Generate a new key pair.
    ///
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator.
    ///
    /// # Returns
    ///
    /// A tuple of (signing_key, verification_key).
    fn keygen(rng: &mut impl CryptoRngCore) -> Result<(Self::SigningKey, Self::VerificationKey)>;

    /// Sign a message.
    ///
    /// # Arguments
    ///
    /// * `sk` - The signing (private) key.
    /// * `message` - The message to sign.
    ///
    /// # Returns
    ///
    /// The signature.
    fn sign(sk: &Self::SigningKey, message: &[u8]) -> Result<Self::Signature>;

    /// Verify a signature.
    ///
    /// # Arguments
    ///
    /// * `pk` - The verification (public) key.
    /// * `message` - The message that was signed.
    /// * `signature` - The signature to verify.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid, `Err(Error::VerificationFailed)` otherwise.
    fn verify(
        pk: &Self::VerificationKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<()>;
}
