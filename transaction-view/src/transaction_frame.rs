use {
    agave_native_auth::NativeAuthEntry,
    crate::{
        address_table_lookup_frame::{AddressTableLookupFrame, AddressTableLookupIterator},
        bytes::{advance_offset_for_type, read_byte},
        instructions_frame::{InstructionsFrame, InstructionsIterator},
        message_header_frame::MessageHeaderFrame,
        result::{Result, TransactionViewError},
        signature_frame::SignatureFrame,
        static_account_keys_frame::StaticAccountKeysFrame,
        transaction_version::TransactionVersion,
    },
    solana_hash::Hash,
    solana_pubkey::Pubkey,
    solana_signature::Signature,
};

const TRANSACTION_V1_ESCAPE_PREFIX: u8 = 0;
const TRANSACTION_V1_NUMBER: u8 = 1;

#[derive(Debug)]
pub(crate) struct TransactionFrame {
    /// Signature framing data.
    signature: SignatureFrame,
    /// The outer transaction version.
    version: TransactionVersion,
    /// Message header framing data.
    message_header: MessageHeaderFrame,
    /// Static account keys framing data.
    static_account_keys: StaticAccountKeysFrame,
    /// Recent blockhash offset.
    recent_blockhash_offset: usize,
    /// Instructions framing data.
    instructions: InstructionsFrame,
    /// Address table lookup framing data.
    address_table_lookup: AddressTableLookupFrame,
}

impl TransactionFrame {
    /// Parse a serialized transaction and verify basic structure.
    /// The `bytes` parameter must have no trailing data.
    pub(crate) fn try_new(bytes: &[u8]) -> Result<Self> {
        let mut offset = 0;
        let first_byte = read_byte(bytes, &mut offset)?;

        let (mut signature, version) = if first_byte == TRANSACTION_V1_ESCAPE_PREFIX {
            let version = read_byte(bytes, &mut offset)?;
            if version != TRANSACTION_V1_NUMBER {
                return Err(TransactionViewError::ParseError);
            }
            (SignatureFrame::try_new_v1(bytes, &mut offset)?, TransactionVersion::V1)
        } else {
            offset = 0;
            (
                SignatureFrame::try_new(bytes, &mut offset)?,
                TransactionVersion::Legacy,
            )
        };

        let message_header = MessageHeaderFrame::try_new(bytes, &mut offset)?;
        let version = match version {
            TransactionVersion::V1 => {
                if !matches!(message_header.version, TransactionVersion::V0) {
                    return Err(TransactionViewError::ParseError);
                }
                TransactionVersion::V1
            }
            _ => message_header.version,
        };

        let static_account_keys = StaticAccountKeysFrame::try_new(bytes, &mut offset)?;

        // The recent blockhash is always present in a valid transaction and
        // has a fixed size of 32 bytes.
        let recent_blockhash_offset = offset;
        advance_offset_for_type::<Hash>(bytes, &mut offset)?;

        let instructions = InstructionsFrame::try_new(bytes, &mut offset)?;
        let address_table_lookup = match version {
            TransactionVersion::Legacy => AddressTableLookupFrame {
                num_address_table_lookups: 0,
                offset: 0,
                total_writable_lookup_accounts: 0,
                total_readonly_lookup_accounts: 0,
            },
            TransactionVersion::V0 | TransactionVersion::V1 => {
                AddressTableLookupFrame::try_new(bytes, &mut offset)?
            }
        };

        // Verify that the entire transaction was parsed.
        if offset != bytes.len() {
            return Err(TransactionViewError::ParseError);
        }

        if signature.is_v1() {
            if signature.num_signatures != message_header.num_required_signatures {
                return Err(TransactionViewError::SanitizeError);
            }
            signature.finalize_v1(&bytes[message_header.offset..]);
        }

        Ok(Self {
            signature,
            version,
            message_header,
            static_account_keys,
            recent_blockhash_offset,
            instructions,
            address_table_lookup,
        })
    }

    /// Return the number of signatures in the transaction.
    #[inline]
    pub(crate) fn num_signatures(&self) -> u8 {
        self.signature.num_signatures
    }

    /// Return the version of the transaction.
    #[inline]
    pub(crate) fn version(&self) -> TransactionVersion {
        self.version
    }

    /// Return native auth entries for v1 transactions.
    #[inline]
    pub(crate) fn native_auth_entries(&self) -> &[NativeAuthEntry] {
        self.signature.native_auth_entries()
    }

    /// Return the stable v1 transaction id, if present.
    #[inline]
    pub(crate) fn transaction_id(&self) -> Option<&Hash> {
        self.signature.transaction_id()
    }

    /// Return the number of required signatures in the transaction.
    #[inline]
    pub(crate) fn num_required_signatures(&self) -> u8 {
        self.message_header.num_required_signatures
    }

    /// Return the number of readonly signed static accounts in the transaction.
    #[inline]
    pub(crate) fn num_readonly_signed_static_accounts(&self) -> u8 {
        self.message_header.num_readonly_signed_accounts
    }

    /// Return the number of readonly unsigned static accounts in the transaction.
    #[inline]
    pub(crate) fn num_readonly_unsigned_static_accounts(&self) -> u8 {
        self.message_header.num_readonly_unsigned_accounts
    }

    /// Return the number of static account keys in the transaction.
    #[inline]
    pub(crate) fn num_static_account_keys(&self) -> u8 {
        self.static_account_keys.num_static_accounts
    }

    /// Return the number of instructions in the transaction.
    #[inline]
    pub(crate) fn num_instructions(&self) -> u16 {
        self.instructions.num_instructions
    }

    /// Return the number of address table lookups in the transaction.
    #[inline]
    pub(crate) fn num_address_table_lookups(&self) -> u8 {
        self.address_table_lookup.num_address_table_lookups
    }

    /// Return the number of writable lookup accounts in the transaction.
    #[inline]
    pub(crate) fn total_writable_lookup_accounts(&self) -> u16 {
        self.address_table_lookup.total_writable_lookup_accounts
    }

    /// Return the number of readonly lookup accounts in the transaction.
    #[inline]
    pub(crate) fn total_readonly_lookup_accounts(&self) -> u16 {
        self.address_table_lookup.total_readonly_lookup_accounts
    }

    /// Return the offset to the message.
    #[inline]
    pub(crate) fn message_offset(&self) -> usize {
        self.message_header.offset
    }
}

// Separate implementation for `unsafe` accessor methods.
impl TransactionFrame {
    /// Return the slice of signatures in the transaction.
    /// # Safety
    ///   - This function must be called with the same `bytes` slice that was
    ///     used to create the `TransactionFrame` instance.
    #[inline]
    pub(crate) unsafe fn signatures<'a>(&'a self, bytes: &'a [u8]) -> &'a [Signature] {
        self.signature.signatures(bytes)
    }

    /// Return the slice of static account keys in the transaction.
    ///
    /// # Safety
    ///  - This function must be called with the same `bytes` slice that was
    ///    used to create the `TransactionFrame` instance.
    #[inline]
    pub(crate) unsafe fn static_account_keys<'a>(&self, bytes: &'a [u8]) -> &'a [Pubkey] {
        // Verify at compile time there are no alignment constraints.
        const _: () = assert!(core::mem::align_of::<Pubkey>() == 1, "Pubkey alignment");

        core::slice::from_raw_parts(
            bytes.as_ptr().add(self.static_account_keys.offset) as *const Pubkey,
            usize::from(self.static_account_keys.num_static_accounts),
        )
    }

    /// Return the recent blockhash in the transaction.
    /// # Safety
    /// - This function must be called with the same `bytes` slice that was
    ///   used to create the `TransactionFrame` instance.
    #[inline]
    pub(crate) unsafe fn recent_blockhash<'a>(&self, bytes: &'a [u8]) -> &'a Hash {
        const _: () = assert!(core::mem::align_of::<Hash>() == 1, "Hash alignment");

        &*(bytes.as_ptr().add(self.recent_blockhash_offset) as *const Hash)
    }

    /// Return an iterator over the instructions in the transaction.
    /// # Safety
    /// - This function must be called with the same `bytes` slice that was
    ///   used to create the `TransactionFrame` instance.
    #[inline]
    pub(crate) unsafe fn instructions_iter<'a>(
        &'a self,
        bytes: &'a [u8],
    ) -> InstructionsIterator<'a> {
        InstructionsIterator {
            bytes,
            offset: self.instructions.offset,
            num_instructions: self.instructions.num_instructions,
            index: 0,
            frames: &self.instructions.frames,
        }
    }

    /// Return an iterator over the address table lookups in the transaction.
    /// # Safety
    /// - This function must be called with the same `bytes` slice that was
    ///   used to create the `TransactionFrame` instance.
    #[inline]
    pub(crate) unsafe fn address_table_lookup_iter<'a>(
        &self,
        bytes: &'a [u8],
    ) -> AddressTableLookupIterator<'a> {
        AddressTableLookupIterator {
            bytes,
            offset: self.address_table_lookup.offset,
            num_address_table_lookups: self.address_table_lookup.num_address_table_lookups,
            index: 0,
        }
    }
}
