use std::time::{Duration, Instant};

use axum::{extract::State, Json};
use tokio::{
    sync::{mpsc, oneshot},
    time::timeout,
};

use crate::{
    base64,
    ds::{
        AddChainInput, AddChainInputParsed, AddChainOutput, Cert, Entry, Error, UnsequencedEntry,
    },
    kv::Storage,
    spec::{hash_leaf, serialize_ct_extensions, serialize_timestamped_entry, sign_sct},
};

#[axum_macros::debug_handler]
pub async fn handle_add_chain(
    State(stage_one_tx): State<mpsc::Sender<UnsequencedEntry>>,
    Json(raw_input): Json<AddChainInput>,
) -> Json<AddChainOutput> {
    // Step 1: Parse and validate the input certificates
    let input = AddChainInputParsed::from(raw_input.clone());

    // Step 2: Create unsequenced timestamped entry
    let (tx, rx) = oneshot::channel();

    let unsequenced_entry = UnsequencedEntry {
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        certs: Cert::X509 {
            cert: input.chain[0].clone(),
            chain: input.chain[1..].to_vec(),
        },
        raw_certs: raw_input
            .chain
            .iter()
            .map(|cert| base64::decode(cert).unwrap())
            .collect(),
        return_path: Some(tx),
    };

    stage_one_tx.send(unsequenced_entry).await.unwrap();

    let entry = rx.await.unwrap();

    todo!();

    // // Step 4: Convert to AddChainOutput
    // let response = AddChainOutput {
    //     sct_version: "V1".to_string(),
    //     id: [0; 32],
    //     timestamp: entry.timestamp,
    //     extensions: base64::encode(serialize_ct_extensions(&entry)),
    //     signature: base64::encode(sign_sct(&entry)),
    // };

    // Json(response)
}

pub async fn stage_one(
    mut stage_one_rx: mpsc::Receiver<UnsequencedEntry>,
    stage_two_tx: mpsc::Sender<Vec<Entry>>,
    starting_sequence: u64,
) {
    let mut sequence = starting_sequence;
    let mut pool: Vec<Entry> = Vec::with_capacity(255);

    const MAX_POOL_SIZE: usize = 255;
    const FLUSH_INTERVAL: Duration = Duration::from_secs(1);

    let mut last_flush_time = Instant::now();

    loop {
        let timeout_future = timeout(FLUSH_INTERVAL, stage_one_rx.recv());
        match timeout_future.await {
            Ok(Some(unsequenced_entry)) => {
                let sequenced_entry = Entry {
                    timestamp: unsequenced_entry.timestamp,
                    certs: unsequenced_entry.certs,
                    raw_certs: unsequenced_entry.raw_certs,
                    return_path: unsequenced_entry.return_path,
                    leaf_index: sequence,
                };

                sequence += 1;

                pool.push(sequenced_entry);

                if pool.len() >= MAX_POOL_SIZE
                    // This condition ensures that the entries in a single pool never cross a tile boundary.
                    // Check the condition after incrementing because the sequence is zero indexed.
                    || sequence % 256 == 0
                    || last_flush_time.elapsed() >= FLUSH_INTERVAL
                {
                    let closed_pool =
                        std::mem::replace(&mut pool, Vec::with_capacity(MAX_POOL_SIZE));
                    stage_two_tx.send(closed_pool).await.unwrap();
                    last_flush_time = Instant::now();
                }
            }
            Ok(None) => {
                // Stage_one_rx channel closed, exit the loop
                break;
            }
            Err(_) => {
                // Timeout occurred, flush the pool
                if !pool.is_empty() {
                    let closed_pool =
                        std::mem::replace(&mut pool, Vec::with_capacity(MAX_POOL_SIZE));
                    stage_two_tx.send(closed_pool).await.unwrap();
                }
                last_flush_time = Instant::now();
            }
        }
    }
}

pub async fn stage_two<T: Storage>(mut stage_two_rx: mpsc::Receiver<Vec<Entry>>, mut database: T) {
    while let Some(pool) = stage_two_rx.recv().await {
        // First, hash and serialize everything in the pool.
        let pool = pool
            .into_iter()
            .map(|entry| {
                let hash = hash_leaf(&entry);
                let serialized = serialize_timestamped_entry(&entry);
                (entry, hash, serialized)
            })
            .collect::<Vec<_>>();

        let mut node_tiles: (usize, Vec<[u8; 32]>) = (0, Vec::new());
        let mut leaf_data_tile: (usize, Vec<Vec<u8>>) = (0, Vec::new());
        let mut leaf_hash_tile: (usize, Vec<[u8; 32]>) = (0, Vec::new());

        // Push all the entries from pool into leaf_data_tile and leaf_hash_tile
        for (entry, hash, serialized) in pool {
            leaf_data_tile.1.push(serialized);
            leaf_hash_tile.1.push(hash);
        }

        // Second, use the sequence of the first entry in the pool to
        // calculate which tiles need to be fetched from s3.
        // let mut last_index = pool[0].0.leaf_index - 1;

        let mut tile_indexes: Vec<i16> = Vec::new();
        // loop {}

        // Third, append all the hashes and serialized data to the
        // level zero tiles.

        // Fourth, update all the parent hashes in the tree up to the root.

        // Fifth, generate a new checkpoint.

        // Sixth, write all updated tiles and checkpoint to s3.

        // Seventh, use the oneshot::Sender to return the entry to
        // the http handler.
    }
}

fn ceil_divide(dividend: u64, divisor: u64) -> u64 {
    (dividend + divisor - 1) / divisor
}

pub async fn get_last_sequence<T: Storage>(database: &T) -> u64 {
    // https://github.com/C2SP/C2SP/blob/main/sunlight.md#sct-extension
    // This section specifies that the sequence is 0-indexed.
    todo!()
}
