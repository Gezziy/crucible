use crate::api::contracts::ApiResponse;
use crate::api::handlers::profiling::AppState;
use crate::config::reload::ConfigManager;
use crate::config::sanitize;
use crate::error::AppError;
use crate::services::contract_call_logger::ContractCallLogger;
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::info;

pub const SESSION_REVOCATION_CHANNEL: &str = "session:revocations";
pub const DEFAULT_REVOCATION_TTL_SECS: u64 = 86_400; // 24 hours

async fn delete_matching_redis_keys(
    conn: &mut redis::aio::MultiplexedConnection,
    pattern: &str,
) -> Result<(), AppError> {
    let mut cursor = 0_u64;
    loop {
        let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(pattern)
            .arg("COUNT")
            .arg(100)
            .query_async(conn)
            .await
            .map_err(AppError::Redis)?;

        if !keys.is_empty() {
            let _: i64 = redis::cmd("DEL")
                .arg(&keys)
                .query_async(conn)
                .await
                .map_err(AppError::Redis)?;
        }

        cursor = next_cursor;
        if cursor == 0 {
            return Ok(());
        }
    }
}

// Global static for maintenance mode (mock implementation)
pub static MAINTENANCE_MODE: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MaintenanceRequest {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemStatsResponse {
    pub database_connected: bool,
    pub redis_connected: bool,
    pub total_contract_calls: i64,
    pub system_uptime_secs: u64,
    pub maintenance_mode: bool,
}

/// GET /api/v1/admin/system-stats
pub async fn get_system_stats(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AppError> {
    let db_connected = if let Some(ref pool) = state.db {
        sqlx::query("SELECT 1").fetch_optional(pool).await.is_ok()
    } else {
        false
    };

    let redis_connected = state.redis.get_async_connection().await.is_ok();

    let total_calls = if let Some(ref pool) = state.db {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM contract_call_logs")
            .fetch_one(pool)
            .await
            .unwrap_or(0)
    } else {
        0
    };

    let metrics = state.metrics_exporter.get_metrics().await;

    Ok(Json(ApiResponse::new(SystemStatsResponse {
        database_connected: db_connected,
        redis_connected,
        total_contract_calls: total_calls,
        system_uptime_secs: metrics.uptime,
        maintenance_mode: MAINTENANCE_MODE.load(Ordering::Relaxed),
    })))
}

/// POST /api/v1/admin/maintenance
pub async fn set_maintenance_mode(
    Json(payload): Json<MaintenanceRequest>,
) -> Result<impl IntoResponse, AppError> {
    MAINTENANCE_MODE.store(payload.enabled, Ordering::Relaxed);
    Ok(Json(ApiResponse::new(serde_json::json!({
        "success": true,
        "maintenanceMode": payload.enabled
    }))))
}

/// GET /api/v1/admin/logs
pub async fn get_admin_logs(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AppError> {
    let db = state
        .db
        .clone()
        .ok_or_else(|| AppError::InternalError("Database connection not configured".to_string()))?;

    let logger = ContractCallLogger::new(db);
    let logs = logger.get_logs(None, 50).await?;

    Ok(Json(ApiResponse::new(logs)))
}

/// GET /api/v1/admin/config
///
/// Returns the current effective configuration with all sensitive fields redacted.
/// This endpoint is intended for operators to inspect non-secret config for diagnostics.
///
/// **Redacted fields:**
/// - `database.url` → `"[REDACTED]"`
/// - `redis.url` → `"[REDACTED]"`
/// - `redis.job_queue_url` → `"[REDACTED]"`
/// - `server.tls.key_path` → `"[REDACTED]"`
pub async fn get_effective_config(
    State(config_manager): State<Arc<ConfigManager>>,
) -> Result<impl IntoResponse, AppError> {
    let config = config_manager.load();
    let sanitized = sanitize::sanitize(&config);
    Ok(Json(ApiResponse::new(sanitized)))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuspendUserRequest {
    pub reason: Option<String>,
    pub jtis: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeRoleRequest {
    pub new_role: Option<String>,
    pub reason: Option<String>,
    pub jtis: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRevocationResponse {
    pub success: bool,
    pub user_id: i32,
    pub revoked_jtis_count: usize,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRevocationEvent {
    pub event_type: String,
    pub user_id: i32,
    pub revoked_jtis: Vec<String>,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
}

/// POST /api/v1/admin/users/:id/suspend
///
/// Suspends a compromised user account.
/// 1. Updates `users.is_active = false` in PostgreSQL.
/// 2. Discovers all active session `jti` tokens from Redis and adds them to `token_blocklist:{jti}` with TTL.
/// 3. Marks `user_suspended:{user_id}` in Redis without automatic expiry.
/// 4. Evicts active Redis session keys and permission/role caches.
/// 5. Broadcasts a session revocation event via Redis Pub/Sub (`session:revocations`).
pub async fn suspend_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i32>,
    payload: Option<Json<SuspendUserRequest>>,
) -> Result<impl IntoResponse, AppError> {
    // 1. Update PostgreSQL users.is_active = false
    let pool = state.db.as_ref().ok_or_else(|| {
        AppError::InternalError("database is required for user suspension".to_string())
    })?;
    let result = sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(AppError::Database)?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("User {user_id} not found")));
    }

    // 2. Redis session invalidation & JTI blacklisting. PostgreSQL remains the
    // authoritative suspension state if any Redis operation fails afterward.
    let mut conn = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(AppError::Redis)?;

    let sessions_key = format!("user_sessions:{user_id}");
    let mut jtis: Vec<String> = conn
        .smembers(&sessions_key)
        .await
        .map_err(AppError::Redis)?;

    let req_data = payload.map(|p| p.0);
    if let Some(ref req) = req_data {
        if let Some(ref extra_jtis) = req.jtis {
            for jti in extra_jtis {
                if !jtis.contains(jti) {
                    jtis.push(jti.clone());
                }
            }
        }
    }

    let reason_str = req_data
        .as_ref()
        .and_then(|p| p.reason.clone())
        .unwrap_or_else(|| "User account suspended by administrator".to_string());

    // Blacklist each active JTI in Redis
    for jti in &jtis {
        let block_key = format!("token_blocklist:{jti}");
        let entry = serde_json::json!({
            "jti": jti,
            "revoked_at": Utc::now(),
            "reason": reason_str,
        });
        let val = serde_json::to_string(&entry).map_err(AppError::Serialization)?;
        let _: () = conn
            .set_ex(block_key, val, DEFAULT_REVOCATION_TTL_SECS)
            .await
            .map_err(AppError::Redis)?;
    }

    // Set user suspension flag in Redis
    let suspended_key = format!("user_suspended:{user_id}");
    let suspended_val = serde_json::json!({
        "userId": user_id,
        "suspendedAt": Utc::now(),
        "reason": reason_str,
    });
    // The database is authoritative for JWT principals; this persistent sentinel
    // also blocks static registry principals until an explicit reinstatement flow
    // removes it.
    let _: () = conn
        .set(
            suspended_key,
            serde_json::to_string(&suspended_val).map_err(AppError::Serialization)?,
        )
        .await
        .map_err(AppError::Redis)?;

    // Evict active session set and cache keys
    let _: () = conn.del(&sessions_key).await.map_err(AppError::Redis)?;
    let role_key = format!("role:{user_id}");
    let _: () = conn.del(role_key).await.map_err(AppError::Redis)?;
    let perm_pattern = format!("perm:{user_id}:*");
    delete_matching_redis_keys(&mut conn, &perm_pattern).await?;

    // 3. Broadcast session revocation event across Redis Pub/Sub
    let event = SessionRevocationEvent {
        event_type: "user_suspended".to_string(),
        user_id,
        revoked_jtis: jtis.clone(),
        reason: reason_str,
        timestamp: Utc::now(),
    };
    let event_payload = serde_json::to_string(&event).map_err(AppError::Serialization)?;
    let _: i64 = conn
        .publish(SESSION_REVOCATION_CHANNEL, event_payload)
        .await
        .map_err(AppError::Redis)?;

    info!(
        user_id,
        revoked_jtis_count = jtis.len(),
        "User suspended and sessions revoked"
    );

    Ok(Json(ApiResponse::new(SessionRevocationResponse {
        success: true,
        user_id,
        revoked_jtis_count: jtis.len(),
        message: format!(
            "User {user_id} suspended and {} session token(s) revoked",
            jtis.len()
        ),
    })))
}

/// POST /api/v1/admin/users/:id/revoke-role
///
/// Revokes elevated role permissions for a user.
/// 1. Updates `users.role` to a lower role in PostgreSQL and removes specific user_permissions.
/// 2. Blacklists active session `jti` tokens associated with the elevated privileges.
/// 3. Evicts cached `role:{user_id}` and `perm:{user_id}:*` in Redis.
/// 4. Broadcasts a role revocation event via Redis Pub/Sub (`session:revocations`).
pub async fn revoke_user_role(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i32>,
    payload: Option<Json<RevokeRoleRequest>>,
) -> Result<impl IntoResponse, AppError> {
    let req_data = payload.map(|p| p.0);
    let target_role = req_data
        .as_ref()
        .and_then(|p| p.new_role.clone())
        .unwrap_or_else(|| "guest".to_string());
    if !matches!(target_role.as_str(), "admin" | "user" | "guest") {
        return Err(AppError::BadRequest(format!(
            "Unsupported role '{target_role}'"
        )));
    }

    let reason_str = req_data
        .as_ref()
        .and_then(|p| p.reason.clone())
        .unwrap_or_else(|| "User role revoked by administrator".to_string());

    // 1. Update role in PostgreSQL
    let pool = state.db.as_ref().ok_or_else(|| {
        AppError::InternalError("database is required for role revocation".to_string())
    })?;
    let mut tx = pool.begin().await.map_err(AppError::Database)?;
    let result = sqlx::query("UPDATE users SET role = $1::user_role WHERE id = $2")
        .bind(&target_role)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("User {user_id} not found")));
    }

    sqlx::query("DELETE FROM user_permissions WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;
    tx.commit().await.map_err(AppError::Database)?;

    // 2. Invalidate Redis role & permission caches and blacklist active tokens
    let mut conn = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(AppError::Redis)?;

    let sessions_key = format!("user_sessions:{user_id}");
    let mut jtis: Vec<String> = conn
        .smembers(&sessions_key)
        .await
        .map_err(AppError::Redis)?;

    if let Some(ref req) = req_data {
        if let Some(ref extra_jtis) = req.jtis {
            for jti in extra_jtis {
                if !jtis.contains(jti) {
                    jtis.push(jti.clone());
                }
            }
        }
    }

    for jti in &jtis {
        let block_key = format!("token_blocklist:{jti}");
        let entry = serde_json::json!({
            "jti": jti,
            "revoked_at": Utc::now(),
            "reason": format!("Role revoked to {target_role}: {reason_str}"),
        });
        let val = serde_json::to_string(&entry).map_err(AppError::Serialization)?;
        let _: () = conn
            .set_ex(block_key, val, DEFAULT_REVOCATION_TTL_SECS)
            .await
            .map_err(AppError::Redis)?;
    }

    let _: () = conn.del(&sessions_key).await.map_err(AppError::Redis)?;
    let role_key = format!("role:{user_id}");
    let _: () = conn.del(role_key).await.map_err(AppError::Redis)?;
    let perm_pattern = format!("perm:{user_id}:*");
    delete_matching_redis_keys(&mut conn, &perm_pattern).await?;

    // 3. Broadcast role revocation event via Redis Pub/Sub
    let event = SessionRevocationEvent {
        event_type: "role_revoked".to_string(),
        user_id,
        revoked_jtis: jtis.clone(),
        reason: format!("Role updated to {target_role}: {reason_str}"),
        timestamp: Utc::now(),
    };
    let event_payload = serde_json::to_string(&event).map_err(AppError::Serialization)?;
    let _: i64 = conn
        .publish(SESSION_REVOCATION_CHANNEL, event_payload)
        .await
        .map_err(AppError::Redis)?;

    info!(
        user_id,
        target_role, "User role revoked and session tokens invalidated"
    );

    Ok(Json(ApiResponse::new(SessionRevocationResponse {
        success: true,
        user_id,
        revoked_jtis_count: jtis.len(),
        message: format!(
            "User {user_id} role revoked to '{target_role}' and {} session token(s) blacklisted",
            jtis.len()
        ),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_revocation_event_serialization() {
        let event = SessionRevocationEvent {
            event_type: "user_suspended".to_string(),
            user_id: 42,
            revoked_jtis: vec!["jti-1".to_string(), "jti-2".to_string()],
            reason: "Compromised credential".to_string(),
            timestamp: Utc::now(),
        };

        let json = serde_json::to_string(&event).expect("must serialize");
        assert!(json.contains("\"eventType\":\"user_suspended\""));
        assert!(json.contains("\"userId\":42"));
        assert!(json.contains("jti-1"));

        let deserialized: SessionRevocationEvent =
            serde_json::from_str(&json).expect("must deserialize");
        assert_eq!(deserialized.user_id, 42);
        assert_eq!(deserialized.revoked_jtis.len(), 2);
    }

    #[test]
    fn test_suspend_user_request_deserialization() {
        let json = r#"{"reason":"Abuse detected","jtis":["token-abc","token-def"]}"#;
        let req: SuspendUserRequest = serde_json::from_str(json).expect("valid json");
        assert_eq!(req.reason.as_deref(), Some("Abuse detected"));
        assert_eq!(req.jtis.unwrap().len(), 2);
    }

    #[test]
    fn test_revoke_role_request_deserialization() {
        let json = r#"{"newRole":"user","reason":"Demoted"}"#;
        let req: RevokeRoleRequest = serde_json::from_str(json).expect("valid json");
        assert_eq!(req.new_role.as_deref(), Some("user"));
        assert_eq!(req.reason.as_deref(), Some("Demoted"));
    }

    #[test]
    fn test_session_revocation_response_structure() {
        let resp = SessionRevocationResponse {
            success: true,
            user_id: 10,
            revoked_jtis_count: 3,
            message: "User 10 suspended".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"userId\":10"));
        assert!(json.contains("\"revokedJtisCount\":3"));
    }
}
