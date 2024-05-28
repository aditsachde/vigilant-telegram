use std::{collections::HashMap, sync::Arc};
use tokio::{sync::Mutex, task::spawn_blocking};

pub trait Storage {
    async fn get(&self, key: &str) -> Option<String>;
    async fn set(&mut self, key: &str, value: String);
    async fn set_many(&mut self, values: Vec<(String, String)>);
}

pub struct WithCache<A: Storage, B: Storage> {
    storage: A,
    cache: B,
}

impl<A: Storage, B: Storage> WithCache<A, B> {
    pub fn new(storage: A, cache: B) -> Self {
        WithCache { storage, cache }
    }
}

impl<A: Storage, B: Storage> Storage for WithCache<A, B> {
    async fn get(&self, key: &str) -> Option<String> {
        if let Some(value) = self.cache.get(key).await {
            return Some(value);
        }

        if let Some(value) = self.storage.get(key).await {
            // self.cache.set(key, value.clone()).await;
            return Some(value);
        }

        None
    }

    async fn set(&mut self, key: &str, value: String) {
        self.storage.set(key, value.clone()).await;
        self.cache.set(key, value).await;
    }

    async fn set_many(&mut self, values: Vec<(String, String)>) {
        self.storage.set_many(values.clone()).await;
        self.cache.set_many(values).await;
    }
}

pub struct InMemoryStorage {
    data: HashMap<String, String>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        InMemoryStorage {
            data: HashMap::new(),
        }
    }
}

impl Storage for InMemoryStorage {
    async fn get(&self, key: &str) -> Option<String> {
        self.data.get(key).cloned()
    }

    async fn set(&mut self, key: &str, value: String) {
        self.data.insert(key.to_string(), value);
    }

    async fn set_many(&mut self, values: Vec<(String, String)>) {
        for (key, value) in values {
            self.data.insert(key, value);
        }
    }
}

#[derive(Clone)]
pub struct MultiThreadedStorage {
    data: Arc<Mutex<HashMap<String, String>>>,
}

impl MultiThreadedStorage {
    pub fn new() -> Self {
        MultiThreadedStorage {
            data: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Storage for MultiThreadedStorage {
    async fn get(&self, key: &str) -> Option<String> {
        let data = self.data.lock().await;
        data.get(key).cloned()
    }

    async fn set(&mut self, key: &str, value: String) {
        let mut data = self.data.lock().await;
        data.insert(key.to_string(), value);
    }

    async fn set_many(&mut self, values: Vec<(String, String)>) {
        let mut data = self.data.lock().await;
        for (key, value) in values {
            data.insert(key, value);
        }
    }
}
