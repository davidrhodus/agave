use {
    agave_native_auth::{
        compatibility_signatures, compute_transaction_id, NativeAuthDescriptor, NativeAuthEntry,
        NativeAuthScheme,
    },
    crate::{
        bytes::{advance_offset_for_array, check_remaining, read_byte, read_compressed_u16},
        result::{Result, TransactionViewError},
    },
    solana_hash::Hash,
    solana_signature::Signature,
};

/// Metadata for accessing transaction-level signatures in a transaction view.
#[derive(Debug, Default)]
pub(crate) struct SignatureFrame {
    /// The number of signatures in the transaction.
    pub(crate) num_signatures: u8,
    /// Offset to the first legacy signature in the transaction.
    pub(crate) offset: usize,
    native_auth_entries: Vec<NativeAuthEntry>,
    compat_signatures: Vec<Signature>,
    transaction_id: Option<Hash>,
}

impl SignatureFrame {
    /// Parse the legacy/v0 signature prefix.
    #[inline(always)]
    pub(crate) fn try_new(bytes: &[u8], offset: &mut usize) -> Result<Self> {
        let num_signatures = read_compressed_u16(bytes, offset)?;
        if num_signatures == 0 || num_signatures > u16::from(u8::MAX) {
            return Err(TransactionViewError::ParseError);
        }

        let signature_offset = *offset;
        advance_offset_for_array::<Signature>(bytes, offset, num_signatures)?;

        Ok(Self {
            num_signatures: num_signatures as u8,
            offset: signature_offset,
            native_auth_entries: Vec::new(),
            compat_signatures: Vec::new(),
            transaction_id: None,
        })
    }

    /// Parse the v1 native auth envelope.
    #[inline(always)]
    pub(crate) fn try_new_v1(bytes: &[u8], offset: &mut usize) -> Result<Self> {
        let num_signatures = read_compressed_u16(bytes, offset)?;
        if num_signatures == 0 || num_signatures > u16::from(u8::MAX) {
            return Err(TransactionViewError::ParseError);
        }

        let mut native_auth_entries = Vec::with_capacity(num_signatures as usize);
        for _ in 0..num_signatures {
            let scheme = NativeAuthScheme::try_from(read_byte(bytes, offset)?)
                .map_err(|_| TransactionViewError::ParseError)?;

            let verifier_key_len = usize::from(read_compressed_u16(bytes, offset)?);
            check_remaining(bytes, *offset, verifier_key_len)?;
            let verifier_key = bytes[*offset..*offset + verifier_key_len].to_vec();
            *offset = offset.wrapping_add(verifier_key_len);

            let proof_len = usize::from(read_compressed_u16(bytes, offset)?);
            check_remaining(bytes, *offset, proof_len)?;
            let proof = bytes[*offset..*offset + proof_len].to_vec();
            *offset = offset.wrapping_add(proof_len);

            native_auth_entries.push(NativeAuthEntry {
                scheme,
                verifier_key,
                proof,
            });
        }

        Ok(Self {
            num_signatures: num_signatures as u8,
            offset: 0,
            native_auth_entries,
            compat_signatures: Vec::new(),
            transaction_id: None,
        })
    }

    #[inline]
    pub(crate) fn is_v1(&self) -> bool {
        !self.native_auth_entries.is_empty()
    }

    #[inline]
    pub(crate) fn native_auth_entries(&self) -> &[NativeAuthEntry] {
        &self.native_auth_entries
    }

    #[inline]
    pub(crate) fn transaction_id(&self) -> Option<&Hash> {
        self.transaction_id.as_ref()
    }

    pub(crate) fn finalize_v1(&mut self, message_bytes: &[u8]) {
        let transaction_id = compute_transaction_id(
            message_bytes,
            self.native_auth_entries
                .iter()
                .map(|entry| NativeAuthDescriptor {
                    scheme: entry.scheme,
                    verifier_key: &entry.verifier_key,
                }),
        );
        self.compat_signatures =
            compatibility_signatures(&transaction_id, self.native_auth_entries.len());
        self.transaction_id = Some(transaction_id);
    }

    /// Return the slice of signatures in the transaction.
    /// # Safety
    ///   - This function must be called with the same `bytes` slice that was
    ///     used to create the `SignatureFrame` instance.
    #[inline]
    pub(crate) unsafe fn signatures<'a>(&'a self, bytes: &'a [u8]) -> &'a [Signature] {
        if self.is_v1() {
            return self.compat_signatures.as_slice();
        }

        // Verify at compile time there are no alignment constraints.
        const _: () = assert!(
            core::mem::align_of::<Signature>() == 1,
            "Signature alignment"
        );

        core::slice::from_raw_parts(
            bytes.as_ptr().add(self.offset) as *const Signature,
            usize::from(self.num_signatures),
        )
    }
}

#[cfg(test)]
mod tests {
    use {super::*, solana_short_vec::ShortVec};

    #[test]
    fn test_zero_signatures() {
        let bytes = bincode::serialize(&ShortVec(Vec::<Signature>::new())).unwrap();
        let mut offset = 0;
        assert!(SignatureFrame::try_new(&bytes, &mut offset).is_err());
    }

    #[test]
    fn test_one_signature() {
        let bytes = bincode::serialize(&ShortVec(vec![Signature::default()])).unwrap();
        let mut offset = 0;
        let frame = SignatureFrame::try_new(&bytes, &mut offset).unwrap();
        assert_eq!(frame.num_signatures, 1);
        assert_eq!(frame.offset, 1);
        assert_eq!(offset, 1 + core::mem::size_of::<Signature>());
    }

    #[test]
    fn test_non_zero_offset() {
        let mut bytes = bincode::serialize(&ShortVec(vec![Signature::default()])).unwrap();
        bytes.insert(0, 0);
        let mut offset = 1;
        let frame = SignatureFrame::try_new(&bytes, &mut offset).unwrap();
        assert_eq!(frame.num_signatures, 1);
        assert_eq!(frame.offset, 2);
        assert_eq!(offset, 2 + core::mem::size_of::<Signature>());
    }

    #[test]
    fn test_v1_single_entry() {
        let bytes = bincode::serialize(&ShortVec(vec![NativeAuthEntry {
            scheme: NativeAuthScheme::Ed25519,
            verifier_key: vec![1u8; 32],
            proof: vec![2u8; 64],
        }]))
        .unwrap();
        let mut offset = 0;
        let frame = SignatureFrame::try_new_v1(&bytes, &mut offset).unwrap();
        assert_eq!(frame.num_signatures, 1);
        assert_eq!(frame.native_auth_entries().len(), 1);
        assert_eq!(offset, bytes.len());
    }
}
