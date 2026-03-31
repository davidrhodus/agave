use {
    crate::versioned::VersionedTransaction,
    agave_native_auth::NativeAuthEntry,
    solana_hash::Hash,
    solana_message::SanitizedVersionedMessage,
    solana_sanitize::SanitizeError,
    solana_signature::Signature,
};

/// Wraps a sanitized `VersionedTransaction` to provide a safe API
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SanitizedVersionedTransaction {
    /// List of signatures
    pub(crate) signatures: Vec<Signature>,
    /// Scheme-tagged native auth entries for v1 transactions.
    pub(crate) native_auth_entries: Vec<NativeAuthEntry>,
    /// Message to sign.
    pub(crate) message: SanitizedVersionedMessage,
}

impl TryFrom<VersionedTransaction> for SanitizedVersionedTransaction {
    type Error = SanitizeError;
    fn try_from(tx: VersionedTransaction) -> Result<Self, Self::Error> {
        Self::try_new(tx)
    }
}

impl SanitizedVersionedTransaction {
    pub fn try_new(tx: VersionedTransaction) -> Result<Self, SanitizeError> {
        tx.sanitize_signatures()?;
        Ok(Self {
            signatures: tx.signatures,
            native_auth_entries: tx.native_auth_entries,
            message: SanitizedVersionedMessage::try_from(tx.message)?,
        })
    }

    pub fn get_message(&self) -> &SanitizedVersionedMessage {
        &self.message
    }

    pub fn native_auth_entries(&self) -> &[NativeAuthEntry] {
        &self.native_auth_entries
    }

    pub fn is_v1(&self) -> bool {
        !self.native_auth_entries.is_empty()
    }

    #[cfg(feature = "blake3")]
    pub fn transaction_id(&self) -> Hash {
        VersionedTransaction {
            signatures: self.signatures.clone(),
            message: self.message.message.clone(),
            native_auth_entries: self.native_auth_entries.clone(),
        }
        .transaction_id()
    }

    /// Consumes the SanitizedVersionedTransaction, returning the fields individually.
    pub fn destruct(self) -> (Vec<Signature>, Vec<NativeAuthEntry>, SanitizedVersionedMessage) {
        (self.signatures, self.native_auth_entries, self.message)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        solana_hash::Hash,
        solana_message::{v0, VersionedMessage},
        solana_pubkey::Pubkey,
    };

    #[test]
    fn test_try_new_with_invalid_signatures() {
        let tx = VersionedTransaction {
            signatures: vec![],
            message: VersionedMessage::V0(
                v0::Message::try_compile(&Pubkey::new_unique(), &[], &[], Hash::default()).unwrap(),
            ),
            native_auth_entries: vec![],
        };

        assert_eq!(
            SanitizedVersionedTransaction::try_new(tx),
            Err(SanitizeError::IndexOutOfBounds)
        );
    }

    #[test]
    fn test_try_new() {
        let mut message =
            v0::Message::try_compile(&Pubkey::new_unique(), &[], &[], Hash::default()).unwrap();
        message.header.num_readonly_signed_accounts += 1;

        let tx = VersionedTransaction {
            signatures: vec![Signature::default()],
            message: VersionedMessage::V0(message),
            native_auth_entries: vec![],
        };

        assert_eq!(
            SanitizedVersionedTransaction::try_new(tx),
            Err(SanitizeError::InvalidValue)
        );
    }
}
