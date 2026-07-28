use std::error::Error;
use std::time::Duration;

use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use base64::Engine;
use rand::seq::SliceRandom;
use rand::Rng;
use rsa::pkcs8::EncodePublicKey;
use rsa::RsaPrivateKey;
use uuid::Uuid;

use crate::data::INTERACT_SERVERS;

type Aes128Cfb = cfb_mode::Decryptor<aes::Aes128>;
type OastResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

/// interact.sh out-of-band callback client (port of the Python `Interactsh`).
pub struct Interactsh {
    private_key: RsaPrivateKey,
    pub domain: String,
    correlation_id: String,
    secret: String,
    server: String,
    headers: Vec<(String, String)>,
    client: reqwest::Client,
}

impl Interactsh {
    /// Generate keys, pick a server and register the correlation id.
    pub async fn new(token: &str, server: &str) -> OastResult<Self> {
        let (this, encoded) = Self::prepare(token, server)?;
        this.register(&encoded).await?;
        Ok(this)
    }

    /// All non-IO setup. Kept sync so the !Send ThreadRng never
    /// leaks into the async future state.
    fn prepare(token: &str, server: &str) -> OastResult<(Self, String)> {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
        let public_key = rsa::RsaPublicKey::from(&private_key);
        let public_pem = public_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF)?;

        let server = server.trim_start_matches('.').to_string();
        let server = if server.is_empty() {
            INTERACT_SERVERS
                .choose(&mut rng)
                .unwrap_or(&"interact.sh")
                .to_string()
        } else {
            server
        };

        let secret = Uuid::new_v4().to_string();
        let encoded = base64::engine::general_purpose::STANDARD.encode(public_pem.as_bytes());

        // same guid mangling as the Python version
        let guid_hex = format!("{:a<33}", Uuid::new_v4().simple().to_string());
        let guid: String = guid_hex
            .chars()
            .map(|c| {
                if c.is_ascii_digit() {
                    c
                } else {
                    char::from_u32(c as u32 + rng.gen_range(0..=20)).unwrap_or(c)
                }
            })
            .collect();
        let domain = format!("{guid}.{server}");
        let correlation_id = domain.chars().take(20).collect::<String>();

        let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];
        if !token.is_empty() {
            headers.push(("Authorization".to_string(), token.to_string()));
        }

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok((
            Interactsh {
                private_key,
                domain,
                correlation_id,
                secret,
                server,
                headers,
                client,
            },
            encoded,
        ))
    }

    async fn register(&self, encoded_public_key: &str) -> OastResult<()> {
        let data = serde_json::json!({
            "public-key": encoded_public_key,
            "secret-key": self.secret,
            "correlation-id": self.correlation_id,
        });
        let mut builder = self
            .client
            .post(format!("https://{}/register", self.server))
            .json(&data);
        for (k, v) in &self.headers {
            builder = builder.header(k, v);
        }
        let res = builder.send().await?;
        let text = res.text().await?;
        if !text.contains("success") {
            return Err("Can not initiate interact.sh DNS callback client".into());
        }
        Ok(())
    }

    /// Poll and decrypt the callback logs.
    pub async fn pull_logs(&self) -> OastResult<Vec<serde_json::Value>> {
        let url = format!(
            "https://{}/poll?id={}&secret={}",
            self.server, self.correlation_id, self.secret
        );
        let mut builder = self.client.get(url);
        for (k, v) in &self.headers {
            builder = builder.header(k, v);
        }
        let res: serde_json::Value = builder.send().await?.json().await?;
        let aes_key = res["aes_key"].as_str().unwrap_or("");
        let data_list = res["data"].as_array().cloned().unwrap_or_default();
        let mut result = Vec::new();
        for entry in data_list {
            if let Some(data) = entry.as_str() {
                let plain = self.decrypt_data(aes_key, data)?;
                let log_entry: serde_json::Value = serde_json::from_slice(&plain)?;
                result.push(serde_json::json!({
                    "timestamp": log_entry["timestamp"],
                    "host": format!("{}.{}", log_entry["full-id"].as_str().unwrap_or(""), self.domain),
                    "remote_address": log_entry["remote-address"],
                }));
            }
        }
        Ok(result)
    }

    fn decrypt_data(&self, aes_key: &str, data: &str) -> OastResult<Vec<u8>> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let encrypted_key = b64.decode(aes_key)?;
        let padding = rsa::Oaep::new::<sha2::Sha256>();
        let aes_plain_key = self.private_key.decrypt(padding, &encrypted_key)?;

        let decoded = b64.decode(data)?;
        if decoded.len() < 16 {
            return Err("interact.sh payload too short".into());
        }
        let (iv, crypt) = decoded.split_at(16);
        let mut buf = crypt.to_vec();
        let cipher = Aes128Cfb::new_from_slices(&aes_plain_key, iv)
            .map_err(|e| format!("bad AES key/iv: {e}"))?;
        cipher.decrypt(&mut buf);
        Ok(buf)
    }
}

/// odiss.eu callback helper (port of the Python `Odiss`).
pub struct Odiss {
    pub key: String,
    pub host: String,
    client: reqwest::Client,
}

impl Default for Odiss {
    fn default() -> Self {
        Self::new()
    }
}

impl Odiss {
    pub fn new() -> Self {
        Odiss {
            key: String::new(),
            host: String::new(),
            client: reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap_or_default(),
        }
    }

    /// Generate a new callback host.
    pub async fn new_host(&mut self) -> OastResult<String> {
        let mut key_bytes = [0u8; 32];
        {
            let mut rng = rand::thread_rng();
            rng.fill(&mut key_bytes);
        }
        self.key = base64::engine::general_purpose::STANDARD.encode(key_bytes);
        let res: serde_json::Value = self
            .client
            .get("https://odiss.eu:1337/events")
            .header("Authorization", format!("Secret {}", self.key))
            .send()
            .await?
            .json()
            .await?;
        self.host = format!("{}.odiss.eu", res["id"].as_str().unwrap_or(""));
        Ok(self.host.clone())
    }

    /// Poll for events; returns the events array when it changed.
    pub async fn poll(&self) -> OastResult<Vec<serde_json::Value>> {
        let res: serde_json::Value = self
            .client
            .get("https://odiss.eu:1337/events")
            .header("Authorization", format!("Secret {}", self.key))
            .send()
            .await?
            .json()
            .await?;
        Ok(res["events"].as_array().cloned().unwrap_or_default())
    }
}
