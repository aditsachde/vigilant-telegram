#![allow(unused)]

use std::future::IntoFuture;

use axum::{routing::post, Router};
use p256::ecdsa::{signature::SignerMut, SigningKey};

mod base64;
mod ctlog;
mod ds;
mod kv;
mod spec;

const SIGNING_KEY: &str = "CoIWDkRxwF87ParupKUoiZeuI9zGgpPUZ+ZP8QutkNE=";

#[tokio::main]
async fn main() {
    let key =
        SigningKey::from_slice(base64::decode(SIGNING_KEY).unwrap().as_slice()).unwrap();

    println!("{}", base64::encode(key.to_bytes()));

    let database = kv::InMemoryStorage::new();

    let last_sequence = ctlog::get_last_sequence(&database).await;
    let (stage_one_tx, stage_one_rx) = tokio::sync::mpsc::channel(255);
    let (stage_two_tx, stage_two_rx) = tokio::sync::mpsc::channel(1);

    let stage_one_handle = tokio::spawn(async move {
        ctlog::stage_one(stage_one_rx, stage_two_tx, last_sequence + 1).await;
    });

    let stage_two_handle = tokio::spawn(async move {
        ctlog::stage_two(stage_two_rx, database).await;
    });

    let app = Router::new()
        .route("/ct/v1/add-chain", post(ctlog::handle_add_chain))
        .route("/ct/v1/add-pre-chain", post(ctlog::handle_add_chain))
        .with_state(stage_one_tx);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    let axum_handle = axum::serve(listener, app).into_future();

    tokio::select! {
        r = axum_handle => r.unwrap(),
        r = stage_one_handle => r.unwrap(),
        r = stage_two_handle => r.unwrap(),
    }
}
