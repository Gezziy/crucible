use axum::{extract::State, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::info;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::api::handlers::profiling::AppState;
use crate::error::AppError;

pub const ALERT_DEDUP_WINDOW_SECONDS: u64 = 300; // 5 minutes
pub const ALERT_DEDUP_KEY_PREFIX: &str = "alert_dedup:";

/// Request body for `POST /api/alerts/ingest`.
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct AlertIngestRequest {
    pub source: String,
    pub message: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default, rename = "alert_type", alias = "alertType")]
    pub alert_type: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

impl AlertIngestRequest {
    /// Resolves the effective alert type from `alert_type`, `severity`, `metadata`, or defaults to `"default"`.
    pub fn resolve_alert_type(&self) -> &str {
        if let Some(ref t) = self.alert_type {
            if !t.trim().is_empty() {
                return t.trim();
            }
        }
        if let Some(ref s) = self.severity {
            if !s.trim().is_empty() {
                return s.trim();
            }
        }
        if let Some(ref meta) = self.metadata {
            if let Some(t) = meta
                .get("alert_type")
                .or_else(|| meta.get("alertType"))
                .and_then(|v| v.as_str())
            {
                if !t.trim().is_empty() {
                    return t.trim();
                }
            }
        }
        "default"
    }
}

/// Computes a deterministic SHA-256 fingerprint for `(alert_type, source, message)`.
pub fn compute_alert_fingerprint(alert_type: &str, source: &str, message: &str) -> String {
    let mut hasher = Sha256::new();
    // Length-prefix each UTF-8 field so delimiters inside a value cannot make
    // two different alert tuples share the same pre-hash representation.
    for value in [alert_type.trim(), source.trim(), message.trim()] {
        let bytes = value.as_bytes();
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    format!("{:x}", hasher.finalize())
}

/// Response body for `POST /api/alerts/ingest`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AlertIngestResponse {
    pub alert_id: String,
    pub accepted: bool,
    pub source: String,
    pub message: String,
    pub severity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deduplicated: Option<bool>,
    pub metadata: Option<Value>,
    pub received_at: DateTime<Utc>,
}

async fn reserve_alert_dedup(
    conn: &mut redis::aio::MultiplexedConnection,
    dedup_key: &str,
    proposed_alert_id: &str,
    ttl_seconds: u64,
) -> Result<(bool, Option<String>), redis::RedisError> {
    let (accepted, stored_alert_id): (i32, Option<String>) = redis::Script::new(
        r#"
        local created = redis.call("SET", KEYS[1], ARGV[1], "NX", "EX", ARGV[2])
        if created then
            return {1, ARGV[1]}
        end
        return {0, redis.call("GET", KEYS[1])}
        "#,
    )
    .key(dedup_key)
    .arg(proposed_alert_id)
    .arg(ttl_seconds)
    .invoke_async(conn)
    .await?;

    Ok((accepted == 1, stored_alert_id))
}

/// Ingests one alert event with 5-minute Redis-backed deduplication.
#[utoipa::path(
    post,
    path = "/api/alerts/ingest",
    request_body = AlertIngestRequest,
    params(
        ("Idempotency-Key" = Option<String>, Header, description = "Optional key used to make retries idempotent for 24 hours")
    ),
    responses(
        (status = 200, description = "Alert ingested", body = AlertIngestResponse),
        (status = 400, description = "Invalid payload")
    ),
    tag = "alerts"
)]
pub async fn ingest_alert(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AlertIngestRequest>,
) -> Result<Json<AlertIngestResponse>, AppError> {
    if payload.source.trim().is_empty() {
        return Err(AppError::BadRequest("source is required".to_string()));
    }
    if payload.message.trim().is_empty() {
        return Err(AppError::BadRequest("message is required".to_string()));
    }

    let alert_type = payload.resolve_alert_type().to_owned();
    let fingerprint = compute_alert_fingerprint(&alert_type, &payload.source, &payload.message);
    let dedup_key = format!("{ALERT_DEDUP_KEY_PREFIX}{fingerprint}");

    let proposed_alert_id = Uuid::new_v4().to_string();

    let mut conn = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(AppError::Redis)?;

    // Reserve the window or return the first alert ID in one atomic operation.
    // This avoids a race between a failed SET NX and a follow-up GET at expiry.
    let (accepted, stored_alert_id) = reserve_alert_dedup(
        &mut conn,
        &dedup_key,
        &proposed_alert_id,
        ALERT_DEDUP_WINDOW_SECONDS,
    )
    .await
    .map_err(AppError::Redis)?;
    let alert_id = stored_alert_id.ok_or_else(|| {
        AppError::InternalError("alert deduplication key disappeared during reservation".into())
    })?;
    if !accepted {
        info!(
            fingerprint = %fingerprint,
            source = %payload.source,
            alert_type = %alert_type,
            "Repetitive alert suppressed within 5-minute deduplication window"
        );
    }

    let response = AlertIngestResponse {
        alert_id,
        accepted,
        source: payload.source,
        message: payload.message,
        severity: payload
            .severity
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "info".to_string()),
        alert_type: Some(alert_type.to_string()),
        deduplicated: Some(!accepted),
        metadata: payload.metadata,
        received_at: Utc::now(),
    };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use redis::AsyncCommands;

    #[test]
    fn test_fingerprint_is_deterministic() {
        let f1 = compute_alert_fingerprint("service_down", "node-1", "High memory usage");
        let f2 = compute_alert_fingerprint("service_down", "node-1", "High memory usage");
        assert_eq!(f1, f2);
        assert_eq!(f1.len(), 64);
    }

    #[test]
    fn test_fingerprint_differentiates_alert_type_source_and_message() {
        let f1 = compute_alert_fingerprint("service_down", "node-1", "High memory usage");
        let f2 = compute_alert_fingerprint("service_up", "node-1", "High memory usage");
        let f3 = compute_alert_fingerprint("service_down", "node-2", "High memory usage");
        let f4 = compute_alert_fingerprint("service_down", "node-1", "Low memory usage");

        assert_ne!(f1, f2);
        assert_ne!(f1, f3);
        assert_ne!(f1, f4);
    }

    #[test]
    fn test_fingerprint_unambiguously_encodes_colons_in_fields() {
        let first = compute_alert_fingerprint("type:a", "source", "message");
        let second = compute_alert_fingerprint("type", "a:source", "message");
        assert_ne!(first, second);
    }

    #[test]
    fn test_resolve_alert_type_priority() {
        let req1 = AlertIngestRequest {
            source: "s".into(),
            message: "m".into(),
            severity: Some("warning".into()),
            alert_type: Some("custom_type".into()),
            metadata: None,
        };
        assert_eq!(req1.resolve_alert_type(), "custom_type");

        let req2 = AlertIngestRequest {
            source: "s".into(),
            message: "m".into(),
            severity: Some("critical".into()),
            alert_type: None,
            metadata: None,
        };
        assert_eq!(req2.resolve_alert_type(), "critical");

        let req3 = AlertIngestRequest {
            source: "s".into(),
            message: "m".into(),
            severity: None,
            alert_type: None,
            metadata: Some(serde_json::json!({ "alertType": "meta_type" })),
        };
        assert_eq!(req3.resolve_alert_type(), "meta_type");

        let req4 = AlertIngestRequest {
            source: "s".into(),
            message: "m".into(),
            severity: None,
            alert_type: None,
            metadata: None,
        };
        assert_eq!(req4.resolve_alert_type(), "default");
    }

    #[test]
    fn test_alert_ingest_request_aliases() {
        let json = r#"{"source":"agent","message":"cpu spike","alertType":"cpu_alert"}"#;
        let req: AlertIngestRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.alert_type.as_deref(), Some("cpu_alert"));
        assert_eq!(req.resolve_alert_type(), "cpu_alert");
    }

    #[test]
    fn test_alert_ingest_response_serialization() {
        let resp = AlertIngestResponse {
            alert_id: "test-id".into(),
            accepted: true,
            source: "node-1".into(),
            message: "disk space low".into(),
            severity: "warning".into(),
            alert_type: Some("storage".into()),
            deduplicated: Some(false),
            metadata: None,
            received_at: Utc::now(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"accepted\":true"));
        assert!(json.contains("\"alert_type\":\"storage\""));
        assert!(json.contains("\"deduplicated\":false"));
    }

    #[tokio::test]
    #[ignore = "requires a Redis service configured with REDIS_URL"]
    async fn redis_dedup_returns_original_id_and_expires_after_ttl() {
        let redis_url = std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let client = redis::Client::open(redis_url).unwrap();
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        let key = format!("test:{ALERT_DEDUP_KEY_PREFIX}{}", Uuid::new_v4());

        let (accepted, first_id) = reserve_alert_dedup(&mut conn, &key, "first-id", 2)
            .await
            .unwrap();
        assert!(accepted);
        assert_eq!(first_id.as_deref(), Some("first-id"));

        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        let (accepted, duplicate_id) = reserve_alert_dedup(&mut conn, &key, "second-id", 2)
            .await
            .unwrap();
        assert!(!accepted);
        assert_eq!(duplicate_id.as_deref(), Some("first-id"));

        // The duplicate must not extend the TTL from its arrival time.
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        let (accepted, expired_id) = reserve_alert_dedup(&mut conn, &key, "third-id", 2)
            .await
            .unwrap();
        assert!(accepted);
        assert_eq!(expired_id.as_deref(), Some("third-id"));

        let _: () = conn.del(key).await.unwrap();
    }
}
