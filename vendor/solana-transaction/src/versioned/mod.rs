//! Defines a transaction which supports multiple versions of messages.

#[cfg(any(feature = "bincode", feature = "serde", feature = "verify"))]
use agave_native_auth::{
    compatibility_signatures, compute_transaction_id, NativeAuthDescriptor, TransactionIdentifier,
};
use agave_native_auth::NativeAuthEntry;
#[cfg(feature = "verify")]
use agave_native_auth::verify_entries;
#[cfg(feature = "bincode")]
use solana_signer::{signers::Signers, SignerError};
use {
    crate::Transaction,
    solana_message::{inline_nonce::is_advance_nonce_instruction_data, VersionedMessage},
    solana_sanitize::SanitizeError,
    solana_sdk_ids::system_program,
    solana_signature::Signature,
    std::cmp::Ordering,
};
#[cfg(feature = "serde")]
use {
    serde::{
        de::{self, SeqAccess, Visitor},
        ser::SerializeTuple,
        Deserialize, Deserializer, Serialize, Serializer,
    },
    serde_derive::{Deserialize as DeriveDeserialize, Serialize as DeriveSerialize},
    solana_short_vec as short_vec,
    std::{fmt, marker::PhantomData},
};

pub mod sanitized;

pub const TRANSACTION_V1_ESCAPE_PREFIX: u8 = 0;
pub const TRANSACTION_V1_NUMBER: u8 = 1;

/// Type that serializes to the string "legacy"
#[cfg_attr(
    feature = "serde",
    derive(DeriveDeserialize, DeriveSerialize),
    serde(rename_all = "camelCase")
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Legacy {
    Legacy,
}

#[cfg_attr(
    feature = "serde",
    derive(DeriveDeserialize, DeriveSerialize),
    serde(rename_all = "camelCase", untagged)
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionVersion {
    Legacy(Legacy),
    Number(u8),
}

impl TransactionVersion {
    pub const LEGACY: Self = Self::Legacy(Legacy::Legacy);
}

// NOTE: Serialization-related changes must be paired with the direct read at sigverify.
/// An atomic transaction
#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VersionedTransaction {
    /// Compatibility signatures for legacy/v0, and deterministic compat
    /// identifiers for v1 native-auth transactions.
    pub signatures: Vec<Signature>,
    /// Message to sign.
    pub message: VersionedMessage,
    /// Native transaction auth entries. Empty for legacy and v0 transactions.
    pub native_auth_entries: Vec<NativeAuthEntry>,
}

impl Default for VersionedTransaction {
    fn default() -> Self {
        Self {
            signatures: Vec::new(),
            message: VersionedMessage::default(),
            native_auth_entries: Vec::new(),
        }
    }
}

impl From<Transaction> for VersionedTransaction {
    fn from(transaction: Transaction) -> Self {
        Self {
            signatures: transaction.signatures,
            message: VersionedMessage::Legacy(transaction.message),
            native_auth_entries: Vec::new(),
        }
    }
}

impl VersionedTransaction {
    /// Signs a versioned message and if successful, returns a signed
    /// transaction.
    #[cfg(feature = "bincode")]
    pub fn try_new<T: Signers + ?Sized>(
        message: VersionedMessage,
        keypairs: &T,
    ) -> std::result::Result<Self, SignerError> {
        let static_account_keys = message.static_account_keys();
        if static_account_keys.len() < message.header().num_required_signatures as usize {
            return Err(SignerError::InvalidInput("invalid message".to_string()));
        }

        let signer_keys = keypairs.try_pubkeys()?;
        let expected_signer_keys =
            &static_account_keys[0..message.header().num_required_signatures as usize];

        match signer_keys.len().cmp(&expected_signer_keys.len()) {
            Ordering::Greater => Err(SignerError::TooManySigners),
            Ordering::Less => Err(SignerError::NotEnoughSigners),
            Ordering::Equal => Ok(()),
        }?;

        let message_data = message.serialize();
        let signature_indexes: Vec<usize> = expected_signer_keys
            .iter()
            .map(|signer_key| {
                signer_keys
                    .iter()
                    .position(|key| key == signer_key)
                    .ok_or(SignerError::KeypairPubkeyMismatch)
            })
            .collect::<std::result::Result<_, SignerError>>()?;

        let unordered_signatures = keypairs.try_sign_message(&message_data)?;
        let signatures: Vec<Signature> = signature_indexes
            .into_iter()
            .map(|index| {
                unordered_signatures
                    .get(index)
                    .copied()
                    .ok_or_else(|| SignerError::InvalidInput("invalid keypairs".to_string()))
            })
            .collect::<std::result::Result<_, SignerError>>()?;

        Ok(Self {
            signatures,
            message,
            native_auth_entries: Vec::new(),
        })
    }

    #[cfg(any(feature = "bincode", feature = "serde", feature = "verify"))]
    fn v1_transaction_id_for_message_and_entries(
        message: &VersionedMessage,
        native_auth_entries: &[NativeAuthEntry],
    ) -> solana_hash::Hash {
        compute_transaction_id(
            &message.serialize(),
            native_auth_entries
                .iter()
                .map(|entry| NativeAuthDescriptor {
                    scheme: entry.scheme,
                    verifier_key: &entry.verifier_key,
                }),
        )
    }

    /// Builds a v1 transaction using scheme-tagged native authentication.
    #[cfg(any(feature = "bincode", feature = "serde", feature = "verify"))]
    pub fn try_new_v1(
        message: VersionedMessage,
        native_auth_entries: Vec<NativeAuthEntry>,
    ) -> std::result::Result<Self, solana_sanitize::SanitizeError> {
        let tx = Self {
            signatures: compatibility_signatures(
                &Self::v1_transaction_id_for_message_and_entries(&message, &native_auth_entries),
                native_auth_entries.len(),
            ),
            message,
            native_auth_entries,
        };
        tx.sanitize()?;
        Ok(tx)
    }

    #[inline]
    pub fn is_v1(&self) -> bool {
        !self.native_auth_entries.is_empty()
    }

    #[inline]
    pub fn native_auth_entries(&self) -> &[NativeAuthEntry] {
        &self.native_auth_entries
    }

    pub fn sanitize(&self) -> std::result::Result<(), SanitizeError> {
        self.message.sanitize()?;
        self.sanitize_signatures()?;
        if self.is_v1() && !matches!(self.message, VersionedMessage::V0(_)) {
            return Err(SanitizeError::InvalidValue);
        }
        Ok(())
    }

    pub(crate) fn sanitize_signatures(&self) -> std::result::Result<(), SanitizeError> {
        if self.is_v1() {
            Self::sanitize_signatures_inner(
                usize::from(self.message.header().num_required_signatures),
                self.message.static_account_keys().len(),
                self.native_auth_entries.len(),
            )
        } else {
            Self::sanitize_signatures_inner(
                usize::from(self.message.header().num_required_signatures),
                self.message.static_account_keys().len(),
                self.signatures.len(),
            )
        }
    }

    pub(crate) fn sanitize_signatures_inner(
        num_required_signatures: usize,
        num_static_account_keys: usize,
        num_signatures: usize,
    ) -> std::result::Result<(), SanitizeError> {
        match num_required_signatures.cmp(&num_signatures) {
            Ordering::Greater => Err(SanitizeError::IndexOutOfBounds),
            Ordering::Less => Err(SanitizeError::InvalidValue),
            Ordering::Equal => Ok(()),
        }?;

        // Signatures are verified before message keys are loaded so all signers
        // must correspond to static account keys.
        if num_signatures > num_static_account_keys {
            return Err(SanitizeError::IndexOutOfBounds);
        }

        Ok(())
    }

    /// Returns the version of the transaction
    pub fn version(&self) -> TransactionVersion {
        if self.is_v1() {
            TransactionVersion::Number(TRANSACTION_V1_NUMBER)
        } else {
            match self.message {
                VersionedMessage::Legacy(_) => TransactionVersion::LEGACY,
                VersionedMessage::V0(_) => TransactionVersion::Number(0),
            }
        }
    }

    /// Returns a legacy transaction if the transaction message is legacy.
    pub fn into_legacy_transaction(self) -> Option<Transaction> {
        if self.is_v1() {
            return None;
        }
        match self.message {
            VersionedMessage::Legacy(message) => Some(Transaction {
                signatures: self.signatures,
                message,
            }),
            _ => None,
        }
    }

    /// Returns the stable transaction identifier. For v1 this is the native
    /// auth txid; for legacy/v0 this remains the canonical message hash.
    #[cfg(feature = "blake3")]
    pub fn transaction_id(&self) -> solana_hash::Hash {
        if self.is_v1() {
            Self::v1_transaction_id_for_message_and_entries(&self.message, &self.native_auth_entries)
        } else {
            let message_bytes = self.message.serialize();
            VersionedMessage::hash_raw_message(&message_bytes)
        }
    }

    /// Returns the canonical external identifier for this transaction.
    #[cfg(any(feature = "bincode", feature = "serde", feature = "verify"))]
    pub fn transaction_identifier(&self) -> TransactionIdentifier {
        if self.is_v1() {
            TransactionIdentifier::Txid(
                Self::v1_transaction_id_for_message_and_entries(&self.message, &self.native_auth_entries),
            )
        } else {
            TransactionIdentifier::Signature(self.signatures.first().copied().unwrap_or_default())
        }
    }

    #[cfg(feature = "verify")]
    /// Verify the transaction and hash its message
    pub fn verify_and_hash_message(
        &self,
    ) -> solana_transaction_error::TransactionResult<solana_hash::Hash> {
        let message_bytes = self.message.serialize();
        if !self
            ._verify_with_results(&message_bytes)
            .iter()
            .all(|verify_result| *verify_result)
        {
            Err(solana_transaction_error::TransactionError::SignatureFailure)
        } else {
            Ok(self.transaction_id())
        }
    }

    #[cfg(feature = "verify")]
    /// Verify the transaction and return a list of verification results
    pub fn verify_with_results(&self) -> Vec<bool> {
        let message_bytes = self.message.serialize();
        self._verify_with_results(&message_bytes)
    }

    #[cfg(feature = "verify")]
    fn _verify_with_results(&self, message_bytes: &[u8]) -> Vec<bool> {
        if self.is_v1() {
            let num_signers = self.native_auth_entries.len();
            match verify_entries(
                message_bytes,
                &self.message.static_account_keys()
                    [..usize::from(self.message.header().num_required_signatures)],
                self.native_auth_entries.iter().map(NativeAuthEntry::as_ref),
            ) {
                Ok(_) => vec![true; num_signers],
                Err(agave_native_auth::NativeAuthError::VerificationFailure { index })
                | Err(agave_native_auth::NativeAuthError::SignerAddressMismatch { index }) => {
                    let mut results = vec![true; num_signers];
                    if let Some(result) = results.get_mut(index) {
                        *result = false;
                    }
                    results
                }
                Err(_) => vec![false; num_signers],
            }
        } else {
            self.signatures
                .iter()
                .zip(self.message.static_account_keys().iter())
                .map(|(signature, pubkey)| signature.verify(pubkey.as_ref(), message_bytes))
                .collect()
        }
    }

    /// Returns true if transaction begins with an advance nonce instruction.
    pub fn uses_durable_nonce(&self) -> bool {
        let message = &self.message;
        message
            .instructions()
            .get(crate::NONCED_TX_MARKER_IX_INDEX as usize)
            .filter(|instruction| {
                // Is system program
                matches!(
                    message.static_account_keys().get(instruction.program_id_index as usize),
                    Some(program_id) if system_program::check_id(program_id)
                ) && is_advance_nonce_instruction_data(&instruction.data)
            })
            .is_some()
    }
}

#[cfg(feature = "serde")]
mod serde_impl {
    use super::*;

    #[derive(DeriveSerialize)]
    struct ShortSignatures<'a>(#[serde(with = "short_vec")] &'a [Signature]);

    #[derive(DeriveSerialize)]
    struct ShortNativeAuthEntries<'a>(#[serde(with = "short_vec")] &'a [NativeAuthEntry]);

    impl Serialize for VersionedTransaction {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if self.is_v1() {
                let mut seq = serializer.serialize_tuple(4)?;
                seq.serialize_element(&TRANSACTION_V1_ESCAPE_PREFIX)?;
                seq.serialize_element(&TRANSACTION_V1_NUMBER)?;
                seq.serialize_element(&ShortNativeAuthEntries(&self.native_auth_entries))?;
                seq.serialize_element(&self.message)?;
                seq.end()
            } else {
                let mut seq = serializer.serialize_tuple(2)?;
                seq.serialize_element(&ShortSignatures(&self.signatures))?;
                seq.serialize_element(&self.message)?;
                seq.end()
            }
        }
    }

    impl<'de> Deserialize<'de> for VersionedTransaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_seq(VersionedTransactionVisitor {
                _marker: PhantomData,
            })
        }
    }

    struct VersionedTransactionVisitor {
        _marker: PhantomData<()>,
    }

    impl<'de> Visitor<'de> for VersionedTransactionVisitor {
        type Value = VersionedTransaction;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a legacy, v0, or v1 versioned transaction")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let first: u8 = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(0, &self))?;

            if first == TRANSACTION_V1_ESCAPE_PREFIX {
                let version: u8 = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                if version != TRANSACTION_V1_NUMBER {
                    return Err(de::Error::custom("unsupported transaction version"));
                }
                let native_auth_entries = deserialize_short_vec::<A, NativeAuthEntry>(&mut seq)?;
                let message: VersionedMessage = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let txid = VersionedTransaction::v1_transaction_id_for_message_and_entries(
                    &message,
                    &native_auth_entries,
                );
                Ok(VersionedTransaction {
                    signatures: compatibility_signatures(&txid, native_auth_entries.len()),
                    message,
                    native_auth_entries,
                })
            } else {
                let signature_len = decode_short_u16(first, &mut seq)?;
                let signatures = (0..usize::from(signature_len))
                    .map(|index| {
                        seq.next_element()?
                            .ok_or_else(|| de::Error::invalid_length(index + 1, &self))
                    })
                    .collect::<Result<Vec<Signature>, A::Error>>()?;
                let message: VersionedMessage = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(signatures.len() + 1, &self))?;
                Ok(VersionedTransaction {
                    signatures,
                    message,
                    native_auth_entries: Vec::new(),
                })
            }
        }
    }

    fn deserialize_short_vec<'de, A, T>(seq: &mut A) -> Result<Vec<T>, A::Error>
    where
        A: SeqAccess<'de>,
        T: Deserialize<'de>,
    {
        let first: u8 = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(0, &"short vec"))?;
        let len = decode_short_u16(first, seq)?;
        let mut result = Vec::with_capacity(usize::from(len));
        for index in 0..usize::from(len) {
            let value = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(index + 1, &"short vec"))?;
            result.push(value);
        }
        Ok(result)
    }

    fn decode_short_u16<'de, A>(first: u8, seq: &mut A) -> Result<u16, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut value = u16::from(first & 0x7f);
        if first & 0x80 == 0 {
            return Ok(value);
        }

        let second: u8 = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(1, &"short vec length"))?;
        if second == 0 {
            return Err(de::Error::custom("alias short vec length encoding"));
        }
        value |= u16::from(second & 0x7f) << 7;
        if second & 0x80 == 0 {
            return Ok(value);
        }

        let third: u8 = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(2, &"short vec length"))?;
        if third & 0xfc != 0 {
            return Err(de::Error::custom("short vec length overflow"));
        }
        if third & 0x80 != 0 {
            return Err(de::Error::custom("short vec length too long"));
        }
        value |= u16::from(third & 0x03) << 14;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        agave_native_auth::NativeAuthScheme,
        solana_hash::Hash,
        solana_instruction::{AccountMeta, Instruction},
        solana_keypair::Keypair,
        solana_message::{v0, Message as LegacyMessage},
        solana_pubkey::Pubkey,
        solana_signer::Signer,
        solana_system_interface::instruction as system_instruction,
    };

    #[test]
    fn test_try_new() {
        let keypair0 = Keypair::new();
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();

        let message = VersionedMessage::Legacy(LegacyMessage::new(
            &[Instruction::new_with_bytes(
                Pubkey::new_unique(),
                &[],
                vec![
                    AccountMeta::new_readonly(keypair1.pubkey(), true),
                    AccountMeta::new_readonly(keypair2.pubkey(), false),
                ],
            )],
            Some(&keypair0.pubkey()),
        ));

        assert_eq!(
            VersionedTransaction::try_new(message.clone(), &[&keypair0]),
            Err(SignerError::NotEnoughSigners)
        );

        assert_eq!(
            VersionedTransaction::try_new(message.clone(), &[&keypair0, &keypair0]),
            Err(SignerError::KeypairPubkeyMismatch)
        );

        assert_eq!(
            VersionedTransaction::try_new(message.clone(), &[&keypair1, &keypair2]),
            Err(SignerError::KeypairPubkeyMismatch)
        );

        match VersionedTransaction::try_new(message.clone(), &[&keypair0, &keypair1]) {
            Ok(tx) => assert_eq!(tx.verify_with_results(), vec![true; 2]),
            Err(err) => assert_eq!(Some(err), None),
        }

        match VersionedTransaction::try_new(message, &[&keypair1, &keypair0]) {
            Ok(tx) => assert_eq!(tx.verify_with_results(), vec![true; 2]),
            Err(err) => assert_eq!(Some(err), None),
        }
    }

    #[test]
    fn test_try_new_v1_ed25519() {
        let keypair = Keypair::new();
        let message = VersionedMessage::V0(
            v0::Message::try_compile(&keypair.pubkey(), &[], &[], Hash::new_unique()).unwrap(),
        );
        let proof = keypair.sign_message(&message.serialize());
        let tx = VersionedTransaction::try_new_v1(
            message,
            vec![NativeAuthEntry {
                scheme: NativeAuthScheme::Ed25519,
                verifier_key: keypair.pubkey().to_bytes().to_vec(),
                proof: proof.as_ref().to_vec(),
            }],
        )
        .unwrap();
        assert!(tx.is_v1());
        assert_eq!(tx.version(), TransactionVersion::Number(1));
        assert_eq!(tx.verify_with_results(), vec![true]);
    }

    fn nonced_transfer_tx() -> (Pubkey, Pubkey, VersionedTransaction) {
        let from_keypair = Keypair::new();
        let from_pubkey = from_keypair.pubkey();
        let nonce_keypair = Keypair::new();
        let nonce_pubkey = nonce_keypair.pubkey();
        let instructions = [
            system_instruction::advance_nonce_account(&nonce_pubkey, &nonce_pubkey),
            system_instruction::transfer(&from_pubkey, &nonce_pubkey, 42),
        ];
        let message = LegacyMessage::new(&instructions, Some(&nonce_pubkey));
        let tx = Transaction::new(&[&from_keypair, &nonce_keypair], message, Hash::default());
        (from_pubkey, nonce_pubkey, tx.into())
    }

    #[test]
    fn tx_uses_nonce_ok() {
        let (_, _, tx) = nonced_transfer_tx();
        assert!(tx.uses_durable_nonce());
    }

    #[test]
    fn tx_uses_nonce_empty_ix_fail() {
        assert!(!VersionedTransaction::default().uses_durable_nonce());
    }

    #[test]
    fn tx_uses_nonce_bad_prog_id_idx_fail() {
        let (_, _, mut tx) = nonced_transfer_tx();
        match &mut tx.message {
            VersionedMessage::Legacy(message) => {
                message.instructions.get_mut(0).unwrap().program_id_index = 255u8;
            }
            VersionedMessage::V0(_) => unreachable!(),
        };
        assert!(!tx.uses_durable_nonce());
    }

    #[test]
    fn tx_uses_nonce_first_prog_id_not_nonce_fail() {
        let from_keypair = Keypair::new();
        let from_pubkey = from_keypair.pubkey();
        let nonce_keypair = Keypair::new();
        let nonce_pubkey = nonce_keypair.pubkey();
        let instructions = [
            system_instruction::transfer(&from_pubkey, &nonce_pubkey, 42),
            system_instruction::advance_nonce_account(&nonce_pubkey, &nonce_pubkey),
        ];
        let message = LegacyMessage::new(&instructions, Some(&from_pubkey));
        let tx = Transaction::new(&[&from_keypair, &nonce_keypair], message, Hash::default());
        let tx = VersionedTransaction::from(tx);
        assert!(!tx.uses_durable_nonce());
    }

    #[test]
    fn tx_uses_nonce_wrong_first_nonce_ix_fail() {
        let from_keypair = Keypair::new();
        let from_pubkey = from_keypair.pubkey();
        let nonce_keypair = Keypair::new();
        let nonce_pubkey = nonce_keypair.pubkey();
        let instructions = [
            system_instruction::withdraw_nonce_account(
                &nonce_pubkey,
                &nonce_pubkey,
                &from_pubkey,
                42,
            ),
            system_instruction::transfer(&from_pubkey, &nonce_pubkey, 42),
        ];
        let message = LegacyMessage::new(&instructions, Some(&nonce_pubkey));
        let tx = Transaction::new(&[&from_keypair, &nonce_keypair], message, Hash::default());
        let tx = VersionedTransaction::from(tx);
        assert!(!tx.uses_durable_nonce());
    }

    #[test]
    fn test_sanitize_signatures_inner() {
        assert_eq!(
            VersionedTransaction::sanitize_signatures_inner(1, 1, 0),
            Err(SanitizeError::IndexOutOfBounds)
        );
        assert_eq!(
            VersionedTransaction::sanitize_signatures_inner(1, 1, 2),
            Err(SanitizeError::InvalidValue)
        );
        assert_eq!(
            VersionedTransaction::sanitize_signatures_inner(2, 1, 2),
            Err(SanitizeError::IndexOutOfBounds)
        );
        assert_eq!(
            VersionedTransaction::sanitize_signatures_inner(1, 1, 1),
            Ok(())
        );
    }
}
