#[cfg(feature = "ml-dsa-44")]
mod ml_dsa_44;
#[cfg(feature = "ml-dsa-65")]
mod ml_dsa_65;
#[cfg(feature = "ml-dsa-87")]
mod ml_dsa_87;

#[cfg(feature = "ml-dsa-44")]
pub use ml_dsa_44::{
    MlDsa44Keypair, MlDsa44Provider, ML_DSA_44_PUBLIC_KEY_LEN, ML_DSA_44_SEED_LEN, ML_DSA_44_SIGNATURE_LEN,
};
#[cfg(feature = "ml-dsa-65")]
pub use ml_dsa_65::{
    MlDsa65Keypair, MlDsa65Provider, ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SEED_LEN, ML_DSA_65_SIGNATURE_LEN,
};
#[cfg(feature = "ml-dsa-87")]
pub use ml_dsa_87::{
    MlDsa87Keypair, MlDsa87Provider, ML_DSA_87_PUBLIC_KEY_LEN, ML_DSA_87_SEED_LEN, ML_DSA_87_SIGNATURE_LEN,
};

/// Copy a caller-supplied ML-DSA seed into a fixed-size buffer that is wiped
/// when it goes out of scope, so signing and key derivation do not leave a
/// stray copy of the private key on the stack.
#[cfg(any(feature = "ml-dsa-44", feature = "ml-dsa-65", feature = "ml-dsa-87"))]
fn seed_array<const N: usize>(seed: &[u8]) -> Result<zeroize::Zeroizing<[u8; N]>, crate::error::CryptoError> {
    if seed.len() != N {
        return Err(crate::error::CryptoError::InvalidSignatureSeedLength);
    }
    let mut out = zeroize::Zeroizing::new([0u8; N]);
    out.copy_from_slice(seed);
    Ok(out)
}
