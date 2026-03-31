use {
    crate::versioned::{sanitized::SanitizedVersionedTransaction, VersionedTransaction},
    agave_native_auth::NativeAuthEntry,
    solana_address::Address,
    solana_hash::Hash,
    solana_message::{
        legacy,
        v0::{self, LoadedAddresses},
        AddressLoader, LegacyMessage, SanitizedMessage, SanitizedVersionedMessage,
        VersionedMessage,
    },
    solana_signature::Signature,
    solana_transaction_error::{TransactionError, TransactionResult},
    std::collections::HashSet,
};
#[cfg(feature = "blake3")]
use {crate::Transaction, solana_sanitize::Sanitize};
#[cfg(feature = "verify")]
use agave_native_auth::{verify_entries, NativeAuthEntryRef};

/// Maximum number of accounts that a transaction may lock.
/// 128 was chosen because it is the minimum number of accounts
/// needed for the Neon EVM implementation.
pub const MAX_TX_ACCOUNT_LOCKS: usize = 128;

/// Sanitized transaction and the hash of its message
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SanitizedTransaction {
    message: SanitizedMessage,
    message_hash: Hash,
    is_simple_vote_tx: bool,
    signatures: Vec<Signature>,
    native_auth_entries: Vec<NativeAuthEntry>,
}

/// Set of accounts that must be locked for safe transaction processing
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct TransactionAccountLocks<'a> {
    /// List of readonly account key locks
    pub readonly: Vec<&'a Address>,
    /// List of writable account key locks
    pub writable: Vec<&'a Address>,
}

/// Type that represents whether the transaction message has been precomputed or
/// not.
pub enum MessageHash {
    Precomputed(Hash),
    Compute,
}

impl From<Hash> for MessageHash {
    fn from(hash: Hash) -> Self {
        Self::Precomputed(hash)
    }
}

impl SanitizedTransaction {
    /// Create a sanitized transaction from a sanitized versioned transaction.
    /// If the input transaction uses address tables, attempt to lookup the
    /// address for each table index.
    pub fn try_new(
        tx: SanitizedVersionedTransaction,
        message_hash: Hash,
        is_simple_vote_tx: bool,
        address_loader: impl AddressLoader,
        reserved_account_keys: &HashSet<Address>,
    ) -> TransactionResult<Self> {
        let signatures = tx.signatures;
        let native_auth_entries = tx.native_auth_entries;
        let SanitizedVersionedMessage { message } = tx.message;
        let message = match message {
            VersionedMessage::Legacy(message) => {
                SanitizedMessage::Legacy(LegacyMessage::new(message, reserved_account_keys))
            }
            VersionedMessage::V0(message) => {
                let loaded_addresses =
                    address_loader.load_addresses(&message.address_table_lookups)?;
                SanitizedMessage::V0(v0::LoadedMessage::new(
                    message,
                    loaded_addresses,
                    reserved_account_keys,
                ))
            }
        };

        Ok(Self {
            message,
            message_hash,
            is_simple_vote_tx,
            signatures,
            native_auth_entries,
        })
    }

    #[cfg(feature = "blake3")]
    /// Create a sanitized transaction from an un-sanitized versioned
    /// transaction.  If the input transaction uses address tables, attempt to
    /// lookup the address for each table index.
    pub fn try_create(
        tx: VersionedTransaction,
        message_hash: impl Into<MessageHash>,
        is_simple_vote_tx: Option<bool>,
        address_loader: impl AddressLoader,
        reserved_account_keys: &HashSet<Address>,
    ) -> TransactionResult<Self> {
        let computed_message_hash = match message_hash.into() {
            MessageHash::Compute => tx.transaction_id(),
            MessageHash::Precomputed(hash) => hash,
        };
        let sanitized_versioned_tx = SanitizedVersionedTransaction::try_from(tx)?;
        let is_simple_vote_tx = is_simple_vote_tx.unwrap_or_else(|| {
            crate::simple_vote_transaction_checker::is_simple_vote_transaction(
                &sanitized_versioned_tx,
            )
        });
        Self::try_new(
            sanitized_versioned_tx,
            computed_message_hash,
            is_simple_vote_tx,
            address_loader,
            reserved_account_keys,
        )
    }

    /// Create a sanitized transaction from a legacy transaction
    #[cfg(feature = "blake3")]
    pub fn try_from_legacy_transaction(
        tx: Transaction,
        reserved_account_keys: &HashSet<Address>,
    ) -> TransactionResult<Self> {
        tx.sanitize()?;

        Ok(Self {
            message_hash: tx.message.hash(),
            message: SanitizedMessage::Legacy(LegacyMessage::new(
                tx.message,
                reserved_account_keys,
            )),
            is_simple_vote_tx: false,
            signatures: tx.signatures,
            native_auth_entries: Vec::new(),
        })
    }

    /// Create a sanitized transaction from a legacy transaction. Used for tests only.
    #[cfg(feature = "blake3")]
    pub fn from_transaction_for_tests(tx: Transaction) -> Self {
        let empty_key_set = HashSet::default();
        Self::try_from_legacy_transaction(tx, &empty_key_set).unwrap()
    }

    /// Create a sanitized transaction from fields.
    /// Performs only basic signature sanitization.
    pub fn try_new_from_fields(
        message: SanitizedMessage,
        message_hash: Hash,
        is_simple_vote_tx: bool,
        signatures: Vec<Signature>,
    ) -> TransactionResult<Self> {
        Self::try_new_from_fields_with_native_auth(
            message,
            message_hash,
            is_simple_vote_tx,
            signatures,
            Vec::new(),
        )
    }

    /// Create a sanitized transaction from fields, preserving v1 native auth.
    pub fn try_new_from_fields_with_native_auth(
        message: SanitizedMessage,
        message_hash: Hash,
        is_simple_vote_tx: bool,
        signatures: Vec<Signature>,
        native_auth_entries: Vec<NativeAuthEntry>,
    ) -> TransactionResult<Self> {
        VersionedTransaction::sanitize_signatures_inner(
            usize::from(message.header().num_required_signatures),
            message.static_account_keys().len(),
            if native_auth_entries.is_empty() {
                signatures.len()
            } else {
                native_auth_entries.len()
            },
        )?;

        Ok(Self {
            message,
            message_hash,
            signatures,
            is_simple_vote_tx,
            native_auth_entries,
        })
    }

    /// Return the first signature for this transaction.
    ///
    /// Notes:
    ///
    /// Sanitized transactions must have at least one signature because the
    /// number of signatures must be greater than or equal to the message header
    /// value `num_required_signatures` which must be greater than 0 itself.
    pub fn signature(&self) -> &Signature {
        &self.signatures[0]
    }

    /// Return the list of signatures for this transaction
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    pub fn is_v1(&self) -> bool {
        !self.native_auth_entries.is_empty()
    }

    /// Return the canonical transaction-id hash used internally for status tracking.
    pub fn transaction_id(&self) -> &Hash {
        &self.message_hash
    }

    pub fn native_auth_entries(&self) -> &[NativeAuthEntry] {
        &self.native_auth_entries
    }

    /// Return the signed message
    pub fn message(&self) -> &SanitizedMessage {
        &self.message
    }

    /// Return the hash of the signed message
    pub fn message_hash(&self) -> &Hash {
        &self.message_hash
    }

    /// Returns true if this transaction is a simple vote
    pub fn is_simple_vote_transaction(&self) -> bool {
        self.is_simple_vote_tx
    }

    /// Convert this sanitized transaction into a versioned transaction for
    /// recording in the ledger.
    pub fn to_versioned_transaction(&self) -> VersionedTransaction {
        let signatures = self.signatures.clone();
        let native_auth_entries = self.native_auth_entries.clone();
        match &self.message {
            SanitizedMessage::V0(sanitized_msg) => VersionedTransaction {
                signatures,
                message: VersionedMessage::V0(v0::Message::clone(&sanitized_msg.message)),
                native_auth_entries,
            },
            SanitizedMessage::Legacy(legacy_message) => VersionedTransaction {
                signatures,
                message: VersionedMessage::Legacy(legacy::Message::clone(&legacy_message.message)),
                native_auth_entries,
            },
        }
    }

    /// Validate and return the account keys locked by this transaction
    pub fn get_account_locks(
        &self,
        tx_account_lock_limit: usize,
    ) -> TransactionResult<TransactionAccountLocks<'_>> {
        Self::validate_account_locks(self.message(), tx_account_lock_limit)?;
        Ok(self.get_account_locks_unchecked())
    }

    /// Return the list of accounts that must be locked during processing this transaction.
    pub fn get_account_locks_unchecked(&self) -> TransactionAccountLocks<'_> {
        let message = &self.message;
        let account_keys = message.account_keys();
        let num_readonly_accounts = message.num_readonly_accounts();
        let num_writable_accounts = account_keys.len().saturating_sub(num_readonly_accounts);

        let mut account_locks = TransactionAccountLocks {
            writable: Vec::with_capacity(num_writable_accounts),
            readonly: Vec::with_capacity(num_readonly_accounts),
        };

        for (i, key) in account_keys.iter().enumerate() {
            if message.is_writable(i) {
                account_locks.writable.push(key);
            } else {
                account_locks.readonly.push(key);
            }
        }

        account_locks
    }

    /// Return the list of addresses loaded from on-chain address lookup tables
    pub fn get_loaded_addresses(&self) -> LoadedAddresses {
        match &self.message {
            SanitizedMessage::Legacy(_) => LoadedAddresses::default(),
            SanitizedMessage::V0(message) => LoadedAddresses::clone(&message.loaded_addresses),
        }
    }

    /// If the transaction uses a durable nonce, return the pubkey of the nonce account
    #[cfg(feature = "bincode")]
    pub fn get_durable_nonce(&self) -> Option<&Address> {
        self.message.get_durable_nonce()
    }

    #[cfg(feature = "verify")]
    /// Return the serialized message data to sign.
    fn message_data(&self) -> Vec<u8> {
        match &self.message {
            SanitizedMessage::Legacy(legacy_message) => legacy_message.message.serialize(),
            SanitizedMessage::V0(loaded_msg) => loaded_msg.message.serialize(),
        }
    }

    #[cfg(feature = "verify")]
    /// Verify the transaction signatures
    pub fn verify(&self) -> TransactionResult<()> {
        let message_bytes = self.message_data();
        if self.is_v1() {
            verify_entries(
                &message_bytes,
                &self.message.static_account_keys()
                    [..usize::from(self.message.header().num_required_signatures)],
                self.native_auth_entries.iter().map(|entry| NativeAuthEntryRef {
                    scheme: entry.scheme,
                    verifier_key: &entry.verifier_key,
                    proof: &entry.proof,
                }),
            )
            .map(|_| ())
            .map_err(|_| TransactionError::SignatureFailure)
        } else {
            if self
                .signatures
                .iter()
                .zip(self.message.account_keys().iter())
                .map(|(signature, pubkey)| signature.verify(pubkey.as_ref(), &message_bytes))
                .any(|verified| !verified)
            {
                Err(TransactionError::SignatureFailure)
            } else {
                Ok(())
            }
        }
    }

    /// Validate a transaction message against locked accounts
    pub fn validate_account_locks(
        message: &SanitizedMessage,
        tx_account_lock_limit: usize,
    ) -> TransactionResult<()> {
        if message.has_duplicates() {
            Err(TransactionError::AccountLoadedTwice)
        } else if message.account_keys().len() > tx_account_lock_limit {
            Err(TransactionError::TooManyAccountLocks)
        } else {
            Ok(())
        }
    }

    #[cfg(feature = "dev-context-only-utils")]
    pub fn new_for_tests(
        message: SanitizedMessage,
        signatures: Vec<Signature>,
        is_simple_vote_tx: bool,
    ) -> SanitizedTransaction {
        SanitizedTransaction {
            message,
            message_hash: Hash::new_unique(),
            signatures,
            native_auth_entries: Vec::new(),
            is_simple_vote_tx,
        }
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use {
        super::*,
        solana_keypair::Keypair,
        solana_message::{MessageHeader, SimpleAddressLoader},
        solana_signer::Signer,
        solana_vote_interface::{instruction, state::Vote},
    };

    #[test]
    fn test_try_create_simple_vote_tx() {
        let bank_hash = Hash::default();
        let block_hash = Hash::default();
        let empty_key_set = HashSet::default();
        let vote_keypair = Keypair::new();
        let node_keypair = Keypair::new();
        let auth_keypair = Keypair::new();
        let votes = Vote::new(vec![1, 2, 3], bank_hash);
        let vote_ix = instruction::vote(&vote_keypair.pubkey(), &auth_keypair.pubkey(), votes);
        let mut vote_tx = Transaction::new_with_payer(&[vote_ix], Some(&node_keypair.pubkey()));
        vote_tx.partial_sign(&[&node_keypair], block_hash);
        vote_tx.partial_sign(&[&auth_keypair], block_hash);

        // single legacy vote ix, 2 signatures
        {
            let vote_transaction = SanitizedTransaction::try_create(
                VersionedTransaction::from(vote_tx.clone()),
                MessageHash::Compute,
                None,
                SimpleAddressLoader::Disabled,
                &empty_key_set,
            )
            .unwrap();
            assert!(vote_transaction.is_simple_vote_transaction());
        }

        {
            // call side says it is not a vote
            let vote_transaction = SanitizedTransaction::try_create(
                VersionedTransaction::from(vote_tx.clone()),
                MessageHash::Compute,
                Some(false),
                SimpleAddressLoader::Disabled,
                &empty_key_set,
            )
            .unwrap();
            assert!(!vote_transaction.is_simple_vote_transaction());
        }

        // single legacy vote ix, 3 signatures
        vote_tx.signatures.push(Signature::default());
        vote_tx.message.header.num_required_signatures = 3;
        {
            let vote_transaction = SanitizedTransaction::try_create(
                VersionedTransaction::from(vote_tx.clone()),
                MessageHash::Compute,
                None,
                SimpleAddressLoader::Disabled,
                &empty_key_set,
            )
            .unwrap();
            assert!(!vote_transaction.is_simple_vote_transaction());
        }

        {
            // call site says it is simple vote
            let vote_transaction = SanitizedTransaction::try_create(
                VersionedTransaction::from(vote_tx),
                MessageHash::Compute,
                Some(true),
                SimpleAddressLoader::Disabled,
                &empty_key_set,
            )
            .unwrap();
            assert!(vote_transaction.is_simple_vote_transaction());
        }
    }

    #[test]
    fn test_try_new_from_fields() {
        let legacy_message = SanitizedMessage::try_from_legacy_message(
            legacy::Message {
                header: MessageHeader {
                    num_required_signatures: 2,
                    num_readonly_signed_accounts: 1,
                    num_readonly_unsigned_accounts: 1,
                },
                account_keys: vec![
                    Address::new_unique(),
                    Address::new_unique(),
                    Address::new_unique(),
                ],
                ..legacy::Message::default()
            },
            &HashSet::default(),
        )
        .unwrap();

        for is_simple_vote_tx in [false, true] {
            // Not enough signatures
            assert!(SanitizedTransaction::try_new_from_fields(
                legacy_message.clone(),
                Hash::new_unique(),
                is_simple_vote_tx,
                vec![],
            )
            .is_err());
            // Too many signatures
            assert!(SanitizedTransaction::try_new_from_fields(
                legacy_message.clone(),
                Hash::new_unique(),
                is_simple_vote_tx,
                vec![
                    Signature::default(),
                    Signature::default(),
                    Signature::default()
                ],
            )
            .is_err());
            // Correct number of signatures.
            assert!(SanitizedTransaction::try_new_from_fields(
                legacy_message.clone(),
                Hash::new_unique(),
                is_simple_vote_tx,
                vec![Signature::default(), Signature::default()]
            )
            .is_ok());
        }
    }
}
