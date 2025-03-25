// Copyright (c) Zefchain Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use super::CryptoHash;
use crate::{
    crypto::{AccountPublicKey, AccountSignature, BcsSignable},
    identifiers::AccountOwner,
};

/// Wrapper around bytes that can be signed.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignableBytes(Vec<u8>);
impl SignableBytes {
    /// Creates a new `SignableBytes` from the given bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        SignableBytes(bytes)
    }

    /// Returns the inner bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl BcsSignable<'_> for SignableBytes {}

/// A trait for signing keys.
#[trait_variant::make(Send + Sync)]
pub trait Signer {
    /// Generates a new signing key for the Self type.
    /// New secret key is inserted into Signer's memory and the `AccountPublicKey` is returned.
    #[cfg(with_getrandom)]
    fn generate_new(&mut self) -> AccountPublicKey;

    /// Creates a signature for the given `value` using the provided `owner`.
    fn sign(&self, owner: &AccountOwner, value: &CryptoHash) -> Option<AccountSignature>;

    /// Returns the public key corresponding to the given `owner`.
    fn get_public(&self, owner: &AccountOwner) -> Option<AccountPublicKey>;

    /// Returnes whether the given `owner` is a known signer.
    fn contains_key(&self, owner: &AccountOwner) -> bool;

    /// Removes the key for the given `owner`.
    fn remove(&mut self, owner: &AccountOwner) -> bool;

    /// Returns a clone of the `Signer` as a boxed trait object.
    fn clone_box(&self) -> Box<dyn Signer>;

    /// Returns an iterator over the keys in the signer.
    fn keys(&self) -> Vec<(AccountOwner, Vec<u8>)>;
}

impl Clone for Box<dyn Signer> {
    fn clone(&self) -> Box<dyn Signer> {
        self.clone_box()
    }
}

impl Signer for Box<dyn Signer> {
    #[cfg(with_getrandom)]
    fn generate_new(&mut self) -> AccountPublicKey {
        (**self).generate_new()
    }

    fn sign(&self, owner: &AccountOwner, value: &CryptoHash) -> Option<AccountSignature> {
        (**self).sign(owner, value)
    }

    fn get_public(&self, owner: &AccountOwner) -> Option<AccountPublicKey> {
        (**self).get_public(owner)
    }

    fn contains_key(&self, owner: &AccountOwner) -> bool {
        (**self).contains_key(owner)
    }

    fn remove(&mut self, owner: &AccountOwner) -> bool {
        (**self).remove(owner)
    }

    fn clone_box(&self) -> Box<dyn Signer> {
        (**self).clone_box()
    }

    fn keys(&self) -> Vec<(AccountOwner, Vec<u8>)> {
        (**self).keys()
    }
}

// impl Default for Box<dyn Signer> {
//     fn default() -> Self {
//         Box::new(InMemSigner::new(None))
//     }
// }
