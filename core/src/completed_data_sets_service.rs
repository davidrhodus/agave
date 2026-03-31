//! [`CompletedDataSetsService`] is a hub, that runs different operations when a "completed data
//! set", also known as a [`Vec<Entry>`], is received by the validator.
//!
//! Currently, `WindowService` sends [`CompletedDataSetInfo`]s via a `completed_sets_receiver`
//! provided to the [`CompletedDataSetsService`].

use {
    agave_native_auth::TransactionIdentifier,
    crossbeam_channel::{Receiver, RecvTimeoutError, Sender},
    solana_entry::entry::Entry,
    solana_ledger::blockstore::{Blockstore, CompletedDataSetInfo},
    solana_rpc::{max_slots::MaxSlots, rpc_subscriptions::RpcSubscriptions},
    solana_signature::Signature,
    std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread::{self, Builder, JoinHandle},
        time::Duration,
    },
};

pub type CompletedDataSetsReceiver = Receiver<Vec<CompletedDataSetInfo>>;
pub type CompletedDataSetsSender = Sender<Vec<CompletedDataSetInfo>>;

pub struct CompletedDataSetsService {
    thread_hdl: JoinHandle<()>,
}

impl CompletedDataSetsService {
    pub fn new(
        completed_sets_receiver: CompletedDataSetsReceiver,
        blockstore: Arc<Blockstore>,
        rpc_subscriptions: Arc<RpcSubscriptions>,
        exit: Arc<AtomicBool>,
        max_slots: Arc<MaxSlots>,
    ) -> Self {
        let thread_hdl = Builder::new()
            .name("solComplDataSet".to_string())
            .spawn(move || {
                info!("CompletedDataSetsService has started");
                loop {
                    if exit.load(Ordering::Relaxed) {
                        break;
                    }
                    if let Err(RecvTimeoutError::Disconnected) = Self::recv_completed_data_sets(
                        &completed_sets_receiver,
                        &blockstore,
                        &rpc_subscriptions,
                        &max_slots,
                    ) {
                        break;
                    }
                }
                info!("CompletedDataSetsService has stopped");
            })
            .unwrap();
        Self { thread_hdl }
    }

    fn recv_completed_data_sets(
        completed_sets_receiver: &CompletedDataSetsReceiver,
        blockstore: &Blockstore,
        rpc_subscriptions: &RpcSubscriptions,
        max_slots: &Arc<MaxSlots>,
    ) -> Result<(), RecvTimeoutError> {
        const RECV_TIMEOUT: Duration = Duration::from_secs(1);
        let handle_completed_data_set_info = |completed_data_set_info| {
            let CompletedDataSetInfo { slot, indices } = completed_data_set_info;
            match blockstore.get_entries_in_data_block(slot, indices, /*slot_meta:*/ None) {
                Ok(entries) => {
                    let (signatures, transaction_ids) = Self::get_received_transactions(entries);
                    if !signatures.is_empty() {
                        rpc_subscriptions.notify_signatures_received((slot, signatures));
                    }
                    if !transaction_ids.is_empty() {
                        rpc_subscriptions.notify_transactions_received((slot, transaction_ids));
                    }
                }
                Err(e) => warn!("completed-data-set-service deserialize error: {e:?}"),
            }
            slot
        };
        let slots = completed_sets_receiver
            .recv_timeout(RECV_TIMEOUT)
            .map(std::iter::once)?
            .chain(completed_sets_receiver.try_iter())
            .flatten()
            .map(handle_completed_data_set_info);
        if let Some(slot) = slots.max() {
            max_slots.shred_insert.fetch_max(slot, Ordering::Relaxed);
        }
        Ok(())
    }

    fn get_received_transactions(
        entries: Vec<Entry>,
    ) -> (Vec<Signature>, Vec<TransactionIdentifier>) {
        let mut signatures = Vec::new();
        let mut transaction_ids = Vec::new();

        for entry in entries {
            for transaction in entry.transactions {
                let transaction_id = transaction.transaction_identifier();
                if let Some(signature) = transaction_id.signature().copied() {
                    if !transaction.signatures.is_empty() {
                        signatures.push(signature);
                        transaction_ids.push(transaction_id);
                    }
                } else {
                    transaction_ids.push(transaction_id);
                }
            }
        }

        (signatures, transaction_ids)
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread_hdl.join()
    }
}

#[cfg(test)]
pub mod test {
    use {
        super::*,
        agave_native_auth::{
            compute_transaction_id, NativeAuthDescriptor, NativeAuthEntry, NativeAuthScheme,
        },
        solana_hash::Hash,
        solana_keypair::Keypair,
        solana_message::{v0, MessageHeader, VersionedMessage},
        solana_signer::Signer,
        solana_transaction::{versioned::VersionedTransaction, Transaction},
    };

    fn create_test_v1_transaction(payer: &Keypair, recent_blockhash: Hash) -> VersionedTransaction {
        let message = VersionedMessage::V0(v0::Message {
            header: MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 0,
            },
            recent_blockhash,
            account_keys: vec![payer.pubkey()],
            address_table_lookups: vec![],
            instructions: vec![],
        });
        let verifier_key = payer.pubkey().to_bytes().to_vec();
        let txid = compute_transaction_id(
            &message.serialize(),
            [NativeAuthDescriptor {
                scheme: NativeAuthScheme::Ed25519,
                verifier_key: &verifier_key,
            }],
        );
        let mut tx = VersionedTransaction::try_new_v1(
            message,
            vec![NativeAuthEntry {
                scheme: NativeAuthScheme::Ed25519,
                verifier_key,
                proof: vec![],
            }],
        )
        .unwrap();
        tx.native_auth_entries[0].proof = payer.sign_message(txid.as_ref()).as_ref().to_vec();
        assert_eq!(tx.verify_with_results(), vec![true]);
        tx
    }

    #[test]
    fn test_zero_signatures() {
        let tx = Transaction::new_with_payer(&[], None);
        let entries = vec![Entry::new(&Hash::default(), 1, vec![tx])];
        let (signatures, transaction_ids) = CompletedDataSetsService::get_received_transactions(entries);
        assert!(signatures.is_empty());
        assert!(transaction_ids.is_empty());
    }

    #[test]
    fn test_multi_signatures() {
        let kp = Keypair::new();
        let tx =
            Transaction::new_signed_with_payer(&[], Some(&kp.pubkey()), &[&kp], Hash::default());
        let entries = vec![Entry::new(&Hash::default(), 1, vec![tx.clone()])];
        let (signatures, transaction_ids) =
            CompletedDataSetsService::get_received_transactions(entries);
        assert_eq!(signatures.len(), 1);
        assert_eq!(transaction_ids.len(), 1);

        let entries = vec![
            Entry::new(&Hash::default(), 1, vec![tx.clone(), tx.clone()]),
            Entry::new(&Hash::default(), 1, vec![tx]),
        ];
        let (signatures, transaction_ids) =
            CompletedDataSetsService::get_received_transactions(entries);
        assert_eq!(signatures.len(), 3);
        assert_eq!(transaction_ids.len(), 3);
    }

    #[test]
    fn test_v1_transactions_emit_txids_not_compatibility_signatures() {
        let kp = Keypair::new();
        let tx = create_test_v1_transaction(&kp, Hash::default());
        let txid = tx.transaction_identifier();
        let entries = vec![Entry {
            num_hashes: 1,
            hash: Hash::default(),
            transactions: vec![tx],
        }];

        let (signatures, transaction_ids) =
            CompletedDataSetsService::get_received_transactions(entries);
        assert!(signatures.is_empty());
        assert_eq!(transaction_ids, vec![txid]);
        assert_eq!(txid.signature(), None);
    }
}
