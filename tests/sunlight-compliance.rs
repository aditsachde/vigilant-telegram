const SUNLIGHT_YAML: &str = include_str!("./sunlight.yaml");
const INTEGRATION_CONFIG: &str = "integration_config.yaml";
const ROOTS: &str = include_str!("./roots.pem");
const PKCS8_PK: &str = include_str!("./pkcs8.pem");

#[tokio::test]
async fn integrate() {
    let s3 = S3::new();
    s3.start_server().await;

    let wd = tempfile::tempdir().unwrap();

    Command::new("git")
        .args(["clone", "https://github.com/FiloSottile/sunlight.git", "."])
        .current_dir(wd.path())
        .status()
        .unwrap();

    fs::write(wd.path().join(INTEGRATION_CONFIG), SUNLIGHT_YAML).unwrap();
    fs::write(wd.path().join("roots.pem"), ROOTS).unwrap();
    fs::write(wd.path().join("pkcs8.pem"), PKCS8_PK).unwrap();

    let conn = rusqlite::Connection::open(wd.path().join("checkpoints.db")).unwrap();
    conn.execute(
        "CREATE TABLE checkpoints (logID BLOB PRIMARY KEY, checkpoint TEXT)",
        [],
    )
    .unwrap();
    conn.close().unwrap();

    let mut sunlight_handle = Command::new("go")
        .args([
            "run",
            "cmd/sunlight/main.go",
            "cmd/sunlight/slog.go",
            "-c",
            INTEGRATION_CONFIG,
        ])
        .current_dir(wd.path())
        .spawn()
        .unwrap();

    sunlight_handle.wait().unwrap();
}

#[tokio::test]
async fn just_run_s3() {
    let s3 = S3::new();
    s3.start_server().await;

    // block forever
    tokio::signal::ctrl_c().await.unwrap();
}

use std::{collections::HashMap, fs, future::IntoFuture, process::Command, sync::Arc};

use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::HeaderValue,
    response::Response,
    routing::put,
    Router,
};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
struct S3 {
    bucket1: Arc<Mutex<HashMap<String, Bytes>>>,
    bucket2: Arc<Mutex<HashMap<String, Bytes>>>,
    checkpoints: Arc<Mutex<HashMap<String, Bytes>>>,
}

impl S3 {
    fn new() -> Self {
        S3 {
            bucket1: Arc::new(Mutex::new(HashMap::new())),
            bucket2: Arc::new(Mutex::new(HashMap::new())),
            checkpoints: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn put(
        Path((bucket, key)): Path<(String, String)>,
        State(s3): State<S3>,
        value: Bytes,
    ) -> Response<Body> {
        println!("PUT {}/{}", bucket, key);

        if key == "checkpoint" {
            println!("Checkpoint, {:?}", value);
        }

        let etag_header_value: HeaderValue = key.parse().unwrap();

        match bucket.as_str() {
            "bucket1" => {
                s3.bucket1.lock().await.insert(key, value);
            }
            "bucket2" => {
                s3.bucket2.lock().await.insert(key, value);
            }
            "checkpoints" => {
                s3.checkpoints.lock().await.insert(key, value);
            }
            _ => panic!("Invalid bucket"),
        };

        let mut response = Response::new(Body::empty());
        response.headers_mut().insert("ETag", etag_header_value);
        response
    }

    async fn get(
        Path((bucket, key)): Path<(String, String)>,
        State(s3): State<S3>,
    ) -> Response<Body> {
        println!("GET {}/{}", bucket, key);

        let value = match bucket.as_str() {
            "bucket1" => s3.bucket1.lock().await.get(&key).unwrap().clone(),
            "bucket2" => s3.bucket2.lock().await.get(&key).unwrap().clone(),
            "checkpoints" => s3.checkpoints.lock().await.get(&key).unwrap().clone(),
            _ => panic!("Invalid bucket"),
        };

        // Make up an ETag
        let mut response = Response::new(Body::from(value));
        response.headers_mut().insert("ETag", key.parse().unwrap());
        response
    }

    async fn start_server(&self) {
        let app = Router::new()
            .route("/:bucket/:key", put(Self::put).get(Self::get))
            .with_state(self.clone());
        let listener = tokio::net::TcpListener::bind("0.0.0.0:54321")
            .await
            .unwrap();
        let handle = axum::serve(listener, app).into_future();
        tokio::spawn(handle);
    }

    async fn check_equality(&self) -> bool {
        let bucket1 = self.bucket1.lock().await;
        let bucket2 = self.bucket2.lock().await;
        *bucket1 == *bucket2
    }
}
