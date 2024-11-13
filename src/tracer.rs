use primitive_types::H256;
use alloy::primitives::{keccak256, B256, U256};
use alloy_compat::Compat;
use alloy_rlp::{BufMut, Encodable};
use eyre::Result;
use mpt_trie::builder::PartialTrieBuilder;
use reth_exex::ExExContext;
use reth_node_api::FullNodeComponents;
use reth_primitives::{
    Receipt, SealedBlockWithSenders, StorageKey, TransactionSigned,
};
use reth_provider::{StateProvider, StateProviderFactory};
use reth_revm::primitives::state::EvmState;
use reth_trie::StorageMultiProof;
use revm::{
    db::ExecutionTrace,
    primitives::{Account, Address},
};
use std::collections::{HashMap, HashSet, BTreeSet, BTreeMap};
use trace_decoder::{
    BlockTrace, BlockTraceTriePreImages, ContractCodeUsage, SeparateStorageTriesPreImage,
    SeparateTriePreImage, SeparateTriePreImages, TxnInfo, TxnMeta, TxnTrace,
};


pub(crate) fn trace_block<Node: FullNodeComponents>(
    ctx: &mut ExExContext<Node>,
    block: SealedBlockWithSenders,
    receipts: Vec<Option<Receipt>>,
    trace: ExecutionTrace,
    tx_traces: Vec<HashMap<Address, Account>>,
) -> Result<BlockTrace> {
    let db = configure_db(ctx, &block);
    let mut code_db = BTreeSet::new();
    let mut txn_infos = vec![];
    let mut cum_gas = 0;

    for ((tx, tx_trace), receipt) in block
        .into_transactions_ecrecovered()
        .zip(tx_traces.into_iter())
        .zip(receipts.into_iter())
    {
        let receipt = receipt.expect("receipt should be present");
        txn_infos.push(trace_transaction(
            &tx,
            receipt,
            &tx_trace,
            &mut code_db,
            &mut cum_gas,
        ));
    }

    let trie_pre_images = state_witness(db, trace.accounts)?;

    Ok(BlockTrace {
        trie_pre_images,
        code_db,
        txn_info: txn_infos,
    })
}

fn configure_db<Node: FullNodeComponents>(
    ctx: &mut ExExContext<Node>,
    block: &SealedBlockWithSenders,
) -> Box<dyn StateProvider> {
    let block_hash = block.parent_hash;
    ctx.provider().state_by_block_hash(block_hash).unwrap()
}

fn trace_transaction(
    tx: &TransactionSigned,
    receipt: Receipt,
    state: &EvmState,
    code_db: &mut BTreeSet<Vec<u8>>,
    cum_gas: &mut u64,
) -> TxnInfo {
    let meta = TxnMeta {
        byte_code: tx.envelope_encoded().to_vec(),
        gas_used: {
            let previous_cum_gas = std::mem::replace(cum_gas, receipt.cumulative_gas_used);
            receipt.cumulative_gas_used - previous_cum_gas
        },
        new_receipt_trie_node_byte: {
            let mut buf = vec![];
            receipt.with_bloom().encode(&mut buf as &mut dyn BufMut);
            buf
        },
    };

    let traces = state
        .iter()
        .map(|(address, state)| {
            let mut storage_read: BTreeSet<B256> = BTreeSet::new();
            let mut storage_written: BTreeMap<B256, _> = BTreeMap::new();

            for (key, value) in state.storage.clone().into_iter() {
                match value.is_changed() {
                    true => {
                        storage_written.insert(
                            key.into(),
                            value.present_value.compat(),
                        );
                    }
                    false => {
                        storage_read.insert(key.into());
                    }
                }
            }

            let code_usage =
                match state.info.is_empty_code_hash() || state.info.code_hash().eq(&reth_primitives::B256::ZERO) {
                    true => None,
                    false => state.info.code.clone().map(|code| {
                        code_db.insert(
                            code.original_bytes().to_vec(),
                        );
                        match state.is_created() {
                            true => ContractCodeUsage::Write(code.original_bytes().to_vec()),
                            false => ContractCodeUsage::Read(keccak256(state.info.code_hash).compat()),
                        }
                    }),
                };

            let trace = TxnTrace {
                balance: Some(state.info.balance.compat()).filter(|_| state.is_touched()),
                nonce: Some(state.info.nonce.into()).filter(|_| state.is_touched()),
                storage_read: storage_read.into_iter().map(Compat::compat).collect(),
                storage_written: storage_written.into_iter().map(|(k, v)| (k.compat(), v)).collect(),
                code_usage,
                self_destructed: state.is_selfdestructed(),
            };

            (compat::Compat::compat(*address), trace)
        })
        .collect();

    TxnInfo { meta, traces }
}

fn state_witness(
    state: Box<dyn StateProvider>,
    state_access: HashMap<Address, HashSet<U256>>,
) -> Result<BlockTraceTriePreImages> {
    // fetch the state witness
    let state_access: HashMap<Address, Vec<StorageKey>> = state_access
        .into_iter()
        .map(|(k, v)| (k, v.into_iter().map(Into::into).collect()))
        .collect();
    let state_access_accts = state_access.keys().cloned().collect::<Vec<_>>();
    let state_witness = state.multiproof(Default::default(), state_access)?;

    // build the account trie witness
    let mut state_trie_builder =
        PartialTrieBuilder::new(compat::Compat::compat(state_witness.root), Default::default());
    state_trie_builder.insert_proof(
        state_witness
            .account_subtree
            .into_values()
            .map(Into::into)
            .collect(),
    );

    // build the storage trie witnesses
    let mut storage_witnesses: HashMap<H256, SeparateTriePreImage> = state_witness
        .storages
        .into_iter()
        .map(|(hashed_addr, StorageMultiProof { root, subtree })| {
            let mut storage_trie_builder =
                PartialTrieBuilder::new(keccak256(root).compat(), Default::default());
            storage_trie_builder.insert_proof(subtree.into_values().map(Into::into).collect());
            (
                keccak256(hashed_addr).compat(),
                SeparateTriePreImage::Direct(storage_trie_builder.build()),
            )
        })
        .collect();

    for addr in state_access_accts {
        let hashed_addr = keccak256(addr);
        storage_witnesses
            .entry(hashed_addr.compat())
            .or_insert(SeparateTriePreImage::Direct(Default::default()));
    }

    Ok(BlockTraceTriePreImages::Separate(SeparateTriePreImages {
        state: SeparateTriePreImage::Direct(state_trie_builder.build()),
        storage: SeparateStorageTriesPreImage::MultipleTries(storage_witnesses),
    }))
}
