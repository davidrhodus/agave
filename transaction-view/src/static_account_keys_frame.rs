use {
    crate::{
        bytes::{advance_offset_for_array, read_compressed_u16},
        result::{Result, TransactionViewError},
    },
    solana_pubkey::Pubkey,
};

/// Contains metadata about the static account keys in a transaction packet.
#[derive(Debug, Default)]
pub(crate) struct StaticAccountKeysFrame {
    /// The number of static accounts in the transaction.
    pub(crate) num_static_accounts: u8,
    /// The offset to the first static account in the transaction.
    pub(crate) offset: usize,
}

impl StaticAccountKeysFrame {
    #[inline(always)]
    pub(crate) fn try_new(bytes: &[u8], offset: &mut usize) -> Result<Self> {
        let num_static_accounts = read_compressed_u16(bytes, offset)?;
        if num_static_accounts == 0 || num_static_accounts > u16::from(u8::MAX) {
            return Err(TransactionViewError::ParseError);
        }

        let static_accounts_offset = *offset;
        // Update offset for array of static accounts.
        advance_offset_for_array::<Pubkey>(bytes, offset, num_static_accounts)?;

        Ok(Self {
            num_static_accounts: num_static_accounts as u8,
            offset: static_accounts_offset,
        })
    }
}

#[cfg(test)]
mod tests {
    use {super::*, solana_short_vec::ShortVec};

    #[test]
    fn test_zero_accounts() {
        let bytes = bincode::serialize(&ShortVec(Vec::<Pubkey>::new())).unwrap();
        let mut offset = 0;
        assert!(StaticAccountKeysFrame::try_new(&bytes, &mut offset).is_err());
    }

    #[test]
    fn test_one_account() {
        let bytes = bincode::serialize(&ShortVec(vec![Pubkey::default()])).unwrap();
        let mut offset = 0;
        let frame = StaticAccountKeysFrame::try_new(&bytes, &mut offset).unwrap();
        assert_eq!(frame.num_static_accounts, 1);
        assert_eq!(frame.offset, 1);
        assert_eq!(offset, 1 + core::mem::size_of::<Pubkey>());
    }

    #[test]
    fn test_max_accounts() {
        let signatures = vec![Pubkey::default(); usize::from(u8::MAX)];
        let bytes = bincode::serialize(&ShortVec(signatures)).unwrap();
        let mut offset = 0;
        let frame = StaticAccountKeysFrame::try_new(&bytes, &mut offset).unwrap();
        assert_eq!(frame.num_static_accounts, u8::MAX);
        assert_eq!(frame.offset, 1);
        assert_eq!(
            offset,
            2 + usize::from(u8::MAX) * core::mem::size_of::<Pubkey>()
        );
    }

    #[test]
    fn test_too_many_accounts() {
        let signatures = vec![Pubkey::default(); usize::from(u8::MAX) + 1];
        let bytes = bincode::serialize(&ShortVec(signatures)).unwrap();
        let mut offset = 0;
        assert!(StaticAccountKeysFrame::try_new(&bytes, &mut offset).is_err());
    }

    #[test]
    fn test_u16_max_accounts() {
        let signatures = vec![Pubkey::default(); u16::MAX as usize];
        let bytes = bincode::serialize(&ShortVec(signatures)).unwrap();
        let mut offset = 0;
        assert!(StaticAccountKeysFrame::try_new(&bytes, &mut offset).is_err());
    }
}
