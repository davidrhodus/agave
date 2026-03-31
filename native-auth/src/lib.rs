#![cfg_attr(
    not(feature = "agave-unstable-api"),
    deprecated(
        since = "3.1.0",
        note = "This crate has been marked for formal inclusion in the Agave Unstable API. From \
                v4.0.0 onward, the `agave-unstable-api` crate feature must be specified to \
                acknowledge use of an interface that may break without warning."
    )
)]

use {
    core::fmt,
    fn_dsa::{
        signature_size, vrfy_key_size, VerifyingKey, VerifyingKeyStandard, DOMAIN_NONE,
        FN_DSA_LOGN_512, HASH_ID_RAW,
    },
    ml_dsa::{EncodedVerifyingKey, MlDsa44},
    signature::Verifier,
    slh_dsa::Shake128s,
    solana_hash::Hash,
    solana_pubkey::Pubkey,
    solana_sha256_hasher::Hasher,
    solana_signature::Signature,
    std::{convert::TryFrom, str::FromStr},
    thiserror::Error,
};
#[cfg(feature = "serde")]
use {
    serde::{Deserialize, Deserializer, Serialize, Serializer},
    solana_short_vec as short_vec,
};

const ADDRESS_DOMAIN: &[u8] = b"agave-native-auth-address-v1";
const TXID_DOMAIN: &[u8] = b"agave-native-auth-txid-v1";
const COMPAT_SIG_DOMAIN_A: &[u8] = b"agave-native-auth-compat-signature-a-v1";
const COMPAT_SIG_DOMAIN_B: &[u8] = b"agave-native-auth-compat-signature-b-v1";

pub type TransactionId = Hash;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransactionIdentifier {
    Signature(Signature),
    Txid(TransactionId),
}

impl TransactionIdentifier {
    pub fn signature(&self) -> Option<&Signature> {
        match self {
            Self::Signature(signature) => Some(signature),
            Self::Txid(_) => None,
        }
    }

    pub fn txid(&self) -> Option<&TransactionId> {
        match self {
            Self::Signature(_) => None,
            Self::Txid(txid) => Some(txid),
        }
    }
}

impl fmt::Display for TransactionIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signature(signature) => signature.fmt(f),
            Self::Txid(txid) => txid.fmt(f),
        }
    }
}

impl FromStr for TransactionIdentifier {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Ok(signature) = Signature::from_str(value) {
            return Ok(Self::Signature(signature));
        }

        if let Ok(txid) = Hash::from_str(value) {
            return Ok(Self::Txid(txid));
        }

        Err("invalid transaction identifier".to_string())
    }
}

impl From<Signature> for TransactionIdentifier {
    fn from(value: Signature) -> Self {
        Self::Signature(value)
    }
}

impl From<TransactionId> for TransactionIdentifier {
    fn from(value: TransactionId) -> Self {
        Self::Txid(value)
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NativeAuthScheme {
    Ed25519 = 0,
    MlDsa44 = 1,
    FnDsa512 = 2,
    SlhDsaShake128s = 3,
}

impl TryFrom<u8> for NativeAuthScheme {
    type Error = NativeAuthError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ed25519),
            1 => Ok(Self::MlDsa44),
            2 => Ok(Self::FnDsa512),
            3 => Ok(Self::SlhDsaShake128s),
            _ => Err(NativeAuthError::UnknownScheme(value)),
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for NativeAuthScheme {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8((*self).into())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for NativeAuthScheme {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

impl From<NativeAuthScheme> for u8 {
    fn from(value: NativeAuthScheme) -> Self {
        value as u8
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeAuthEntry {
    pub scheme: NativeAuthScheme,
    #[cfg_attr(feature = "serde", serde(with = "short_vec"))]
    pub verifier_key: Vec<u8>,
    #[cfg_attr(feature = "serde", serde(with = "short_vec"))]
    pub proof: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeAuthDescriptor<'a> {
    pub scheme: NativeAuthScheme,
    pub verifier_key: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeAuthEntryRef<'a> {
    pub scheme: NativeAuthScheme,
    pub verifier_key: &'a [u8],
    pub proof: &'a [u8],
}

impl NativeAuthEntry {
    pub fn descriptor(&self) -> NativeAuthDescriptor<'_> {
        NativeAuthDescriptor {
            scheme: self.scheme,
            verifier_key: &self.verifier_key,
        }
    }

    pub fn as_ref(&self) -> NativeAuthEntryRef<'_> {
        NativeAuthEntryRef {
            scheme: self.scheme,
            verifier_key: &self.verifier_key,
            proof: &self.proof,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NativeAuthError {
    #[error("unknown native auth scheme {0}")]
    UnknownScheme(u8),
    #[error("invalid ed25519 verifier key length")]
    InvalidEd25519VerifierKey,
    #[error("invalid ed25519 proof length")]
    InvalidEd25519Proof,
    #[error("invalid ML-DSA-44 verifier key encoding")]
    InvalidMlDsa44VerifierKey,
    #[error("invalid ML-DSA-44 proof encoding")]
    InvalidMlDsa44Proof,
    #[error("invalid FN-DSA-512 verifier key length")]
    InvalidFnDsa512VerifierKey,
    #[error("invalid FN-DSA-512 proof length")]
    InvalidFnDsa512Proof,
    #[error("invalid SLH-DSA-SHAKE-128s verifier key encoding")]
    InvalidSlhDsaShake128sVerifierKey,
    #[error("invalid SLH-DSA-SHAKE-128s proof encoding")]
    InvalidSlhDsaShake128sProof,
    #[error("native auth signer count mismatch: expected {expected}, found {actual}")]
    InvalidSignerCount { expected: usize, actual: usize },
    #[error("native auth signer {index} does not match expected signer address")]
    SignerAddressMismatch { index: usize },
    #[error("native auth proof {index} failed verification")]
    VerificationFailure { index: usize },
}

pub fn compute_transaction_id<'a>(
    message_bytes: &[u8],
    descriptors: impl IntoIterator<Item = NativeAuthDescriptor<'a>>,
) -> TransactionId {
    let mut hasher = Hasher::default();
    hasher.hash(TXID_DOMAIN);
    hasher.hash(message_bytes);
    for descriptor in descriptors {
        hasher.hash(&[u8::from(descriptor.scheme)]);
        append_short_vec(&mut hasher, descriptor.verifier_key);
    }
    hasher.result()
}

pub fn derive_signer_address(
    scheme: NativeAuthScheme,
    verifier_key: &[u8],
) -> Result<Pubkey, NativeAuthError> {
    validate_verifier_key(scheme, verifier_key)?;
    match scheme {
        NativeAuthScheme::Ed25519 => Pubkey::try_from(verifier_key)
            .map_err(|_| NativeAuthError::InvalidEd25519VerifierKey),
        _ => {
            let mut hasher = Hasher::default();
            hasher.hash(ADDRESS_DOMAIN);
            hasher.hash(&[u8::from(scheme)]);
            append_short_vec(&mut hasher, verifier_key);
            Ok(Pubkey::new_from_array(hasher.result().to_bytes()))
        }
    }
}

pub fn compatibility_signatures(txid: &TransactionId, num_signers: usize) -> Vec<Signature> {
    (0..num_signers)
        .map(|index| compatibility_signature(txid, index))
        .collect()
}

pub fn compatibility_signature(txid: &TransactionId, index: usize) -> Signature {
    let index = u16::try_from(index).expect("transaction signer index exceeds u16");
    let index_bytes = index.to_le_bytes();

    let mut hasher = Hasher::default();
    hasher.hash(COMPAT_SIG_DOMAIN_A);
    hasher.hash(txid.as_ref());
    hasher.hash(&index_bytes);
    let prefix = hasher.result();

    let mut hasher = Hasher::default();
    hasher.hash(COMPAT_SIG_DOMAIN_B);
    hasher.hash(txid.as_ref());
    hasher.hash(&index_bytes);
    let suffix = hasher.result();

    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(prefix.as_ref());
    bytes[32..].copy_from_slice(suffix.as_ref());
    Signature::from(bytes)
}

pub fn verify_entries<'a>(
    message_bytes: &[u8],
    expected_signers: &[Pubkey],
    entries: impl IntoIterator<Item = NativeAuthEntryRef<'a>>,
) -> Result<TransactionId, NativeAuthError> {
    let entries = entries.into_iter().collect::<Vec<_>>();
    if entries.len() != expected_signers.len() {
        return Err(NativeAuthError::InvalidSignerCount {
            expected: expected_signers.len(),
            actual: entries.len(),
        });
    }

    let txid = compute_transaction_id(
        message_bytes,
        entries.iter().map(|entry| NativeAuthDescriptor {
            scheme: entry.scheme,
            verifier_key: entry.verifier_key,
        }),
    );

    for (index, (entry, expected_signer)) in entries.iter().zip(expected_signers).enumerate() {
        if derive_signer_address(entry.scheme, entry.verifier_key)? != *expected_signer {
            return Err(NativeAuthError::SignerAddressMismatch { index });
        }
        verify_entry(txid.as_ref(), *entry).map_err(|_| NativeAuthError::VerificationFailure {
            index,
        })?;
    }

    Ok(txid)
}

pub fn validate_verifier_key(
    scheme: NativeAuthScheme,
    verifier_key: &[u8],
) -> Result<(), NativeAuthError> {
    match scheme {
        NativeAuthScheme::Ed25519 => (verifier_key.len() == 32)
            .then_some(())
            .ok_or(NativeAuthError::InvalidEd25519VerifierKey),
        NativeAuthScheme::MlDsa44 => {
            let encoded = EncodedVerifyingKey::<MlDsa44>::try_from(verifier_key)
                .map_err(|_| NativeAuthError::InvalidMlDsa44VerifierKey)?;
            let _ = ml_dsa::VerifyingKey::<MlDsa44>::decode(&encoded);
            Ok(())
        }
        NativeAuthScheme::FnDsa512 => (verifier_key.len() == vrfy_key_size(FN_DSA_LOGN_512))
            .then_some(())
            .ok_or(NativeAuthError::InvalidFnDsa512VerifierKey),
        NativeAuthScheme::SlhDsaShake128s => slh_dsa::VerifyingKey::<Shake128s>::try_from(
            verifier_key,
        )
        .map(|_| ())
        .map_err(|_| NativeAuthError::InvalidSlhDsaShake128sVerifierKey),
    }
}

fn verify_entry(message: &[u8], entry: NativeAuthEntryRef<'_>) -> Result<(), NativeAuthError> {
    match entry.scheme {
        NativeAuthScheme::Ed25519 => {
            let signature =
                Signature::try_from(entry.proof).map_err(|_| NativeAuthError::InvalidEd25519Proof)?;
            if signature.verify(entry.verifier_key, message) {
                Ok(())
            } else {
                Err(NativeAuthError::VerificationFailure { index: 0 })
            }
        }
        NativeAuthScheme::MlDsa44 => {
            let encoded_vk = EncodedVerifyingKey::<MlDsa44>::try_from(entry.verifier_key)
                .map_err(|_| NativeAuthError::InvalidMlDsa44VerifierKey)?;
            let verifying_key = ml_dsa::VerifyingKey::<MlDsa44>::decode(&encoded_vk);
            let signature = ml_dsa::Signature::<MlDsa44>::try_from(entry.proof)
                .map_err(|_| NativeAuthError::InvalidMlDsa44Proof)?;
            verifying_key
                .verify(message, &signature)
                .map_err(|_| NativeAuthError::VerificationFailure { index: 0 })
        }
        NativeAuthScheme::FnDsa512 => {
            if entry.proof.len() != signature_size(FN_DSA_LOGN_512) {
                return Err(NativeAuthError::InvalidFnDsa512Proof);
            }
            let Some(verifying_key) = VerifyingKeyStandard::decode(entry.verifier_key) else {
                return Err(NativeAuthError::InvalidFnDsa512VerifierKey);
            };
            if verifying_key.verify(entry.proof, &DOMAIN_NONE, &HASH_ID_RAW, message) {
                Ok(())
            } else {
                Err(NativeAuthError::VerificationFailure { index: 0 })
            }
        }
        NativeAuthScheme::SlhDsaShake128s => {
            let verifying_key = slh_dsa::VerifyingKey::<Shake128s>::try_from(entry.verifier_key)
                .map_err(|_| NativeAuthError::InvalidSlhDsaShake128sVerifierKey)?;
            let signature = slh_dsa::Signature::<Shake128s>::try_from(entry.proof)
                .map_err(|_| NativeAuthError::InvalidSlhDsaShake128sProof)?;
            verifying_key
                .verify(message, &signature)
                .map_err(|_| NativeAuthError::VerificationFailure { index: 0 })
        }
    }
}

fn append_short_vec(hasher: &mut Hasher, bytes: &[u8]) {
    let mut remaining = bytes.len();
    loop {
        let mut byte = (remaining & 0x7f) as u8;
        remaining >>= 7;
        if remaining != 0 {
            byte |= 0x80;
        }
        hasher.hash(&[byte]);
        if remaining == 0 {
            break;
        }
    }
    hasher.hash(bytes);
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        fn_dsa::{KeyPairGenerator, KeyPairGeneratorStandard, SigningKey as _, SigningKeyStandard},
        ml_dsa::KeyGen,
        signature::{Keypair, SignatureEncoding, Signer},
        slh_dsa::SigningKey as SlhSigningKey,
        solana_keypair::Keypair as Ed25519Keypair,
        solana_message::{v0, MessageHeader, VersionedMessage},
        solana_signer::Signer as SolanaSigner,
    };

    fn empty_message_bytes() -> Vec<u8> {
        VersionedMessage::V0(v0::Message {
            header: MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 0,
            },
            account_keys: vec![Pubkey::new_unique()],
            recent_blockhash: Hash::default(),
            instructions: vec![],
            address_table_lookups: vec![],
        })
        .serialize()
    }

    #[test]
    fn txid_ignores_proof_bytes() {
        let entries = [
            NativeAuthEntry {
                scheme: NativeAuthScheme::Ed25519,
                verifier_key: vec![7; 32],
                proof: vec![1; 64],
            },
            NativeAuthEntry {
                scheme: NativeAuthScheme::Ed25519,
                verifier_key: vec![8; 32],
                proof: vec![2; 64],
            },
        ];
        let mut altered = entries.clone();
        altered[0].proof[0] ^= 1;
        let message = empty_message_bytes();
        assert_eq!(
            compute_transaction_id(&message, entries.iter().map(NativeAuthEntry::descriptor)),
            compute_transaction_id(&message, altered.iter().map(NativeAuthEntry::descriptor))
        );
    }

    #[test]
    fn native_auth_entry_serde_uses_u8_scheme_tag() {
        let bytes = bincode::serialize(&solana_short_vec::ShortVec(vec![NativeAuthEntry {
            scheme: NativeAuthScheme::Ed25519,
            verifier_key: vec![7; 32],
            proof: vec![9; 64],
        }]))
        .unwrap();

        assert_eq!(bytes[0], 1);
        assert_eq!(bytes[1], NativeAuthScheme::Ed25519 as u8);
        assert_eq!(bytes[2], 32);
    }

    #[test]
    fn verify_all_supported_schemes() {
        let message = empty_message_bytes();
        let mut fn_rng = rand::thread_rng();

        let ed_keypair = Ed25519Keypair::new();
        let ed_signer = ed_keypair.pubkey();
        let ed_verifier_key = ed_signer.to_bytes().to_vec();

        let ml_seed: ml_dsa::Seed = [9u8; 32].into();
        let ml_keypair = MlDsa44::from_seed(&ml_seed);
        let ml_verifier = ml_keypair.verifying_key();
        let ml_verifier_key = ml_verifier.encode().as_slice().to_vec();
        let ml_signer =
            derive_signer_address(NativeAuthScheme::MlDsa44, &ml_verifier_key).unwrap();

        let mut fn_keygen = KeyPairGeneratorStandard::default();
        let mut fn_signing_key = vec![0u8; fn_dsa::sign_key_size(FN_DSA_LOGN_512)];
        let mut fn_verifying_key = vec![0u8; vrfy_key_size(FN_DSA_LOGN_512)];
        fn_keygen.keygen(
            FN_DSA_LOGN_512,
            &mut fn_rng,
            &mut fn_signing_key,
            &mut fn_verifying_key,
        );
        let mut fn_signing_key =
            SigningKeyStandard::decode(&fn_signing_key).expect("decode FN-DSA signing key");
        let fn_signer = derive_signer_address(NativeAuthScheme::FnDsa512, &fn_verifying_key).unwrap();

        let slh_keypair =
            SlhSigningKey::<Shake128s>::slh_keygen_internal(&[1u8; 16], &[2u8; 16], &[3u8; 16]);
        let slh_verifier = slh_keypair.verifying_key();
        let slh_verifier_key = slh_verifier.to_bytes().as_slice().to_vec();
        let slh_signer =
            derive_signer_address(NativeAuthScheme::SlhDsaShake128s, &slh_verifier_key).unwrap();

        let txid = compute_transaction_id(
            &message,
            [
                NativeAuthDescriptor {
                    scheme: NativeAuthScheme::Ed25519,
                    verifier_key: &ed_verifier_key,
                },
                NativeAuthDescriptor {
                    scheme: NativeAuthScheme::MlDsa44,
                    verifier_key: &ml_verifier_key,
                },
                NativeAuthDescriptor {
                    scheme: NativeAuthScheme::FnDsa512,
                    verifier_key: &fn_verifying_key,
                },
                NativeAuthDescriptor {
                    scheme: NativeAuthScheme::SlhDsaShake128s,
                    verifier_key: &slh_verifier_key,
                },
            ],
        );
        let txid_bytes = txid.as_ref();

        let ed_signature = ed_keypair.sign_message(txid_bytes);
        assert!(ed_signature.verify(ed_keypair.pubkey().as_ref(), txid_bytes));
        let ed_entry = NativeAuthEntry {
            scheme: NativeAuthScheme::Ed25519,
            verifier_key: ed_verifier_key,
            proof: ed_signature.as_ref().to_vec(),
        };

        let ml_entry = NativeAuthEntry {
            scheme: NativeAuthScheme::MlDsa44,
            verifier_key: ml_verifier_key,
            proof: ml_keypair.signing_key().sign(txid_bytes).to_bytes().to_vec(),
        };

        let mut fn_proof = vec![0u8; signature_size(FN_DSA_LOGN_512)];
        fn_signing_key.sign(
            &mut fn_rng,
            &DOMAIN_NONE,
            &HASH_ID_RAW,
            txid_bytes,
            &mut fn_proof,
        );
        let fn_entry = NativeAuthEntry {
            scheme: NativeAuthScheme::FnDsa512,
            verifier_key: fn_verifying_key,
            proof: fn_proof,
        };

        let slh_entry = NativeAuthEntry {
            scheme: NativeAuthScheme::SlhDsaShake128s,
            verifier_key: slh_verifier_key,
            proof: slh_keypair
                .try_sign(txid_bytes)
                .unwrap()
                .to_bytes()
                .as_slice()
                .to_vec(),
        };

        let result = verify_entries(
            &message,
            &[ed_signer, ml_signer, fn_signer, slh_signer],
            [
                ed_entry.as_ref(),
                ml_entry.as_ref(),
                fn_entry.as_ref(),
                slh_entry.as_ref(),
            ],
        );
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn verify_entries_rejects_invalid_signer_count() {
        let keypair = Ed25519Keypair::new();
        let signer = keypair.pubkey();
        let verifier_key = signer.to_bytes().to_vec();
        let message = empty_message_bytes();
        let txid = compute_transaction_id(
            &message,
            [NativeAuthDescriptor {
                scheme: NativeAuthScheme::Ed25519,
                verifier_key: &verifier_key,
            }],
        );
        let proof = keypair.sign_message(txid.as_ref());
        let entry = NativeAuthEntry {
            scheme: NativeAuthScheme::Ed25519,
            verifier_key,
            proof: proof.as_ref().to_vec(),
        };

        assert_eq!(
            verify_entries(&message, &[], [entry.as_ref()]),
            Err(NativeAuthError::InvalidSignerCount {
                expected: 0,
                actual: 1,
            })
        );
    }

    #[test]
    fn verify_entries_rejects_signer_address_mismatch() {
        let keypair = Ed25519Keypair::new();
        let verifier_key = keypair.pubkey().to_bytes().to_vec();
        let message = empty_message_bytes();
        let txid = compute_transaction_id(
            &message,
            [NativeAuthDescriptor {
                scheme: NativeAuthScheme::Ed25519,
                verifier_key: &verifier_key,
            }],
        );
        let proof = keypair.sign_message(txid.as_ref());
        let entry = NativeAuthEntry {
            scheme: NativeAuthScheme::Ed25519,
            verifier_key,
            proof: proof.as_ref().to_vec(),
        };

        assert_eq!(
            verify_entries(&message, &[Pubkey::new_unique()], [entry.as_ref()]),
            Err(NativeAuthError::SignerAddressMismatch { index: 0 })
        );
    }

    #[test]
    fn verify_entries_rejects_tampered_ed25519_proof() {
        let keypair = Ed25519Keypair::new();
        let signer = keypair.pubkey();
        let verifier_key = signer.to_bytes().to_vec();
        let message = empty_message_bytes();
        let txid = compute_transaction_id(
            &message,
            [NativeAuthDescriptor {
                scheme: NativeAuthScheme::Ed25519,
                verifier_key: &verifier_key,
            }],
        );
        let mut proof = keypair.sign_message(txid.as_ref()).as_ref().to_vec();
        proof[0] ^= 1;
        let entry = NativeAuthEntry {
            scheme: NativeAuthScheme::Ed25519,
            verifier_key,
            proof,
        };

        assert_eq!(
            verify_entries(&message, &[signer], [entry.as_ref()]),
            Err(NativeAuthError::VerificationFailure { index: 0 })
        );
    }

    #[test]
    fn verify_entries_rejects_invalid_scheme_inputs() {
        let message = empty_message_bytes();
        let ed_verifier_key = [7u8; 32];
        let ed_signer = Pubkey::new_from_array(ed_verifier_key);

        assert_eq!(
            NativeAuthScheme::try_from(9),
            Err(NativeAuthError::UnknownScheme(9))
        );
        assert_eq!(
            verify_entries(
                &message,
                &[ed_signer],
                [NativeAuthEntryRef {
                    scheme: NativeAuthScheme::Ed25519,
                    verifier_key: &[7u8; 31],
                    proof: &[9u8; 64],
                }],
            ),
            Err(NativeAuthError::InvalidEd25519VerifierKey)
        );
        assert_eq!(
            verify_entries(
                &message,
                &[ed_signer],
                [NativeAuthEntryRef {
                    scheme: NativeAuthScheme::Ed25519,
                    verifier_key: &ed_verifier_key,
                    proof: &[9u8; 1],
                }],
            ),
            Err(NativeAuthError::VerificationFailure { index: 0 })
        );

        let ml_seed: ml_dsa::Seed = [3u8; 32].into();
        let ml_keypair = MlDsa44::from_seed(&ml_seed);
        let ml_verifier_key = ml_keypair.verifying_key().encode().as_slice().to_vec();
        let ml_signer =
            derive_signer_address(NativeAuthScheme::MlDsa44, &ml_verifier_key).unwrap();
        assert_eq!(
            validate_verifier_key(NativeAuthScheme::MlDsa44, &[1u8; 1]),
            Err(NativeAuthError::InvalidMlDsa44VerifierKey)
        );
        assert!(matches!(
            verify_entries(
                &message,
                &[ml_signer],
                [NativeAuthEntryRef {
                    scheme: NativeAuthScheme::MlDsa44,
                    verifier_key: &ml_verifier_key,
                    proof: &[2u8; 1],
                }],
            ),
            Err(NativeAuthError::InvalidMlDsa44Proof)
                | Err(NativeAuthError::VerificationFailure { index: 0 })
        ));

        let mut fn_rng = rand::thread_rng();
        let mut fn_keygen = KeyPairGeneratorStandard::default();
        let mut fn_signing_key = vec![0u8; fn_dsa::sign_key_size(FN_DSA_LOGN_512)];
        let mut fn_verifier_key = vec![0u8; vrfy_key_size(FN_DSA_LOGN_512)];
        fn_keygen.keygen(
            FN_DSA_LOGN_512,
            &mut fn_rng,
            &mut fn_signing_key,
            &mut fn_verifier_key,
        );
        let fn_signer = derive_signer_address(NativeAuthScheme::FnDsa512, &fn_verifier_key).unwrap();
        assert_eq!(
            validate_verifier_key(NativeAuthScheme::FnDsa512, &[1u8; 1]),
            Err(NativeAuthError::InvalidFnDsa512VerifierKey)
        );
        assert!(matches!(
            verify_entries(
                &message,
                &[fn_signer],
                [NativeAuthEntryRef {
                    scheme: NativeAuthScheme::FnDsa512,
                    verifier_key: &fn_verifier_key,
                    proof: &[2u8; 1],
                }],
            ),
            Err(NativeAuthError::InvalidFnDsa512Proof)
                | Err(NativeAuthError::VerificationFailure { index: 0 })
        ));

        let slh_keypair =
            SlhSigningKey::<Shake128s>::slh_keygen_internal(&[4u8; 16], &[5u8; 16], &[6u8; 16]);
        let slh_verifier_key = slh_keypair.verifying_key().to_bytes().as_slice().to_vec();
        let slh_signer =
            derive_signer_address(NativeAuthScheme::SlhDsaShake128s, &slh_verifier_key).unwrap();
        assert_eq!(
            validate_verifier_key(NativeAuthScheme::SlhDsaShake128s, &[1u8; 1]),
            Err(NativeAuthError::InvalidSlhDsaShake128sVerifierKey)
        );
        assert!(matches!(
            verify_entries(
                &message,
                &[slh_signer],
                [NativeAuthEntryRef {
                    scheme: NativeAuthScheme::SlhDsaShake128s,
                    verifier_key: &slh_verifier_key,
                    proof: &[2u8; 1],
                }],
            ),
            Err(NativeAuthError::InvalidSlhDsaShake128sProof)
                | Err(NativeAuthError::VerificationFailure { index: 0 })
        ));
    }
}
