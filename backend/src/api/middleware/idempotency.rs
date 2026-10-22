use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{header::CONTENT_TYPE, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use redis::AsyncCommands;
use serde_json::json;
use uuid::Uuid;

use crate::api::handlers::profiling::AppState;
use crate::error::AppError;

const IDEMPOTENCY_TTL_SECONDS: u64 = 86_400;
#[cfg(not(test))]
const IDEMPOTENCY_LOCK_TTL_MS: u64 = 60_000;
#[cfg(test)]
const IDEMPOTENCY_LOCK_TTL_MS: u64 = 300;
const IDEMPOTENCY_ROUTE: &str = "/api/alerts/ingest";

/// Releases the distributed idempotency lock atomically using a compare-and-delete Lua script.
///
/// Ensures the lock is only released if it is still held by the owner with matching `token`,
/// preventing accidental deletion of a newer lock acquired after TTL expiration.
async fn release_idempotency_lock(
    conn: &mut redis::aio::MultiplexedConnection,
    lock_key: &str,
    token: &str,
) {
    let script = redis::Script::new(
        r#"
        if redis.call("GET", KEYS[1]) == ARGV[1] then
            return redis.call("DEL", KEYS[1])
        end
        return 0
        "#,
    );
    let _ = script
        .key(lock_key)
        .arg(token)
        .invoke_async::<i32>(conn)
        .await;
}

/// Renews the reservation while the route handler is running. If Redis reports that
/// this request no longer owns the reservation, the caller cancels the handler future.
async fn maintain_idempotency_lock(
    conn: &mut redis::aio::MultiplexedConnection,
    lock_key: &str,
    token: &str,
) -> Result<(), AppError> {
    let script = redis::Script::new(
        r#"
        if redis.call("GET", KEYS[1]) == ARGV[1] then
            return redis.call("PEXPIRE", KEYS[1], ARGV[2])
        end
        return 0
        "#,
    );
    let renewal_interval = std::time::Duration::from_millis(IDEMPOTENCY_LOCK_TTL_MS / 3);

    loop {
        tokio::time::sleep(renewal_interval).await;
        let renewed: i32 = script
            .key(lock_key)
            .arg(token)
            .arg(IDEMPOTENCY_LOCK_TTL_MS)
            .invoke_async(conn)
            .await?;
        if renewed != 1 {
            return Err(AppError::InternalError(
                "idempotency reservation was lost while processing the request".to_string(),
            ));
        }
    }
}

/// Cache successful `POST /api/alerts/ingest` responses by idempotency key with atomic mutual exclusion.
///
/// When `Idempotency-Key` is present:
/// - cache hit: replay the stored body immediately.
/// - cache miss: atomically reserve the key via `SET lock_key token NX PX <ttl>` to prevent concurrent
///   execution races. If reservation fails, reject concurrent requests with `409 Conflict`.
///   On successful `200 OK` execution, persist response in cache and release lock.
pub async fn idempotency_middleware(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let key = request
        .headers()
        .get("Idempotency-Key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());

    let Some(key) = key else {
        return Ok(next.run(request).await);
    };

    let cache_key = format!("idempotency:{IDEMPOTENCY_ROUTE}:{key}");
    let lock_key = format!("lock:idempotency:{IDEMPOTENCY_ROUTE}:{key}");
    let token = Uuid::new_v4().to_string();
    let mut conn = state.redis.get_multiplexed_async_connection().await?;

    // 1. Fast path: check for completed, cached response.
    if let Some(cached_response) = conn.get::<_, Option<String>>(&cache_key).await? {
        let mut response = Response::new(Body::from(cached_response));
        *response.status_mut() = StatusCode::OK;
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        response
            .headers_mut()
            .insert("x-idempotency-replayed", HeaderValue::from_static("true"));
        return Ok(response);
    }

    // 2. Atomic key reservation using SET NX PX to ensure mutual exclusion.
    let lock_acquired: Option<String> = redis::cmd("SET")
        .arg(&lock_key)
        .arg(&token)
        .arg("NX")
        .arg("PX")
        .arg(IDEMPOTENCY_LOCK_TTL_MS)
        .query_async(&mut conn)
        .await?;

    if lock_acquired.is_none() {
        // Double-check if the concurrent request finished while attempting to acquire lock.
        if let Some(cached_response) = conn.get::<_, Option<String>>(&cache_key).await? {
            let mut response = Response::new(Body::from(cached_response));
            *response.status_mut() = StatusCode::OK;
            response
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            response
                .headers_mut()
                .insert("x-idempotency-replayed", HeaderValue::from_static("true"));
            return Ok(response);
        }

        return Err(AppError::Conflict(
            "A request with this idempotency key is currently in progress".to_string(),
        ));
    }

    // 3. Execute handler with reservation held and periodically renew the lease.
    let mut heartbeat_conn = conn.clone();
    let response = tokio::select! {
        response = next.run(request) => response,
        lock_result = maintain_idempotency_lock(&mut heartbeat_conn, &lock_key, &token) => {
            release_idempotency_lock(&mut conn, &lock_key, &token).await;
            return Err(lock_result.expect_err("lock maintenance only exits on failure"));
        }
    };
    if response.status() != StatusCode::OK {
        // Release lock on non-OK responses so client retries are not blocked.
        release_idempotency_lock(&mut conn, &lock_key, &token).await;
        return Ok(response);
    }

    let (parts, body) = response.into_parts();
    let body_bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(error) => {
            release_idempotency_lock(&mut conn, &lock_key, &token).await;
            return Err(AppError::InternalError(format!(
                "failed to read response body: {error}"
            )));
        }
    };

    let body_text = match String::from_utf8(body_bytes.to_vec()) {
        Ok(text) => text,
        Err(error) => {
            release_idempotency_lock(&mut conn, &lock_key, &token).await;
            return Err(AppError::InternalError(format!(
                "response body was not UTF-8: {error}"
            )));
        }
    };

    // 4. Cache successful response and release atomic lock.
    if let Err(error) = conn
        .set_ex::<_, _, ()>(&cache_key, body_text.clone(), IDEMPOTENCY_TTL_SECONDS)
        .await
    {
        release_idempotency_lock(&mut conn, &lock_key, &token).await;
        return Err(error.into());
    }
    release_idempotency_lock(&mut conn, &lock_key, &token).await;

    let mut rebuilt = Response::from_parts(parts, Body::from(body_text));
    rebuilt
        .headers_mut()
        .insert("x-idempotency-replayed", HeaderValue::from_static("false"));
    Ok(rebuilt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::handlers::profiling::AppState,
        config::{reload::ConfigManager, AppConfig},
        services::{
            contract_benchmark::ContractBenchmarkService, error_recovery::ErrorManager,
            log_aggregator::LogAggregator, sys_metrics::MetricsExporter,
        },
    };
    use axum::{middleware, response::IntoResponse, routing::post, Json, Router};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tower::ServiceExt;

    #[tokio::test]
    #[ignore = "requires local Redis server"]
    async fn duplicate_request_replays_original_response() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_handler = counter.clone();

        let redis = redis::Client::open("redis://127.0.0.1:6379").unwrap();
        let app_state = Arc::new(AppState {
            db: None,
            metrics_exporter: Arc::new(MetricsExporter::new()),
            error_manager: Arc::new(ErrorManager::new()),
            config_manager: Arc::new(ConfigManager::new(AppConfig::default())),
            log_aggregator: Arc::new(LogAggregator::new().0),
            contract_benchmark_service: Arc::new(ContractBenchmarkService::new()),
            redis: redis.clone(),
        });

        let app = Router::new()
            .route(
                IDEMPOTENCY_ROUTE,
                post(move || {
                    let counter = counter_for_handler.clone();
                    async move {
                        let value = counter.fetch_add(1, Ordering::SeqCst) + 1;
                        Json(json!({ "request_number": value }))
                    }
                })
                .route_layer(middleware::from_fn_with_state(
                    app_state.clone(),
                    idempotency_middleware,
                )),
            )
            .with_state(app_state);

        let idempotency_key = format!("duplicate-check-{}", Uuid::new_v4());
        let request = || {
            Request::builder()
                .method("POST")
                .uri(IDEMPOTENCY_ROUTE)
                .header("content-type", "application/json")
                .header("Idempotency-Key", idempotency_key.clone())
                .body(Body::from(r#"{"message":"hello"}"#))
                .unwrap()
        };

        let first = app.clone().oneshot(request()).await.unwrap();
        let second = app.oneshot(request()).await.unwrap();

        assert_eq!(
            first.headers().get("x-idempotency-replayed").unwrap(),
            "false"
        );
        assert_eq!(
            second.headers().get("x-idempotency-replayed").unwrap(),
            "true"
        );
        let first_body = to_bytes(first.into_body(), usize::MAX).await.unwrap();
        let second_body = to_bytes(second.into_body(), usize::MAX).await.unwrap();

        assert_eq!(first_body, second_body);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    #[ignore = "requires local Redis server"]
    async fn concurrent_duplicate_requests_one_executes_one_conflicts() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_handler = counter.clone();

        let redis = redis::Client::open("redis://127.0.0.1:6379").unwrap();
        let app_state = Arc::new(AppState {
            db: None,
            metrics_exporter: Arc::new(MetricsExporter::new()),
            error_manager: Arc::new(ErrorManager::new()),
            config_manager: Arc::new(ConfigManager::new(AppConfig::default())),
            log_aggregator: Arc::new(LogAggregator::new().0),
            contract_benchmark_service: Arc::new(ContractBenchmarkService::new()),
            redis: redis.clone(),
        });

        let app = Router::new()
            .route(
                IDEMPOTENCY_ROUTE,
                post(move || {
                    let counter = counter_for_handler.clone();
                    async move {
                        // Run longer than the test lock TTL to verify lease renewal.
                        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
                        let value = counter.fetch_add(1, Ordering::SeqCst) + 1;
                        Json(json!({ "request_number": value }))
                    }
                })
                .route_layer(middleware::from_fn_with_state(
                    app_state.clone(),
                    idempotency_middleware,
                )),
            )
            .with_state(app_state);

        let idempotency_key = format!("concurrent-check-{}", Uuid::new_v4());
        let request = || {
            Request::builder()
                .method("POST")
                .uri(IDEMPOTENCY_ROUTE)
                .header("content-type", "application/json")
                .header("Idempotency-Key", idempotency_key.clone())
                .body(Body::from(r#"{"message":"hello"}"#))
                .unwrap()
        };

        let (first, second) = tokio::join!(app.clone().oneshot(request()), app.oneshot(request()));

        let first = first.unwrap();
        let second = second.unwrap();

        let statuses = [first.status(), second.status()];
        assert!(statuses.contains(&StatusCode::OK));
        assert!(statuses.contains(&StatusCode::CONFLICT));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    #[ignore = "requires local Redis server"]
    async fn failed_handler_releases_lock_allowing_subsequent_retry() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_for_handler = attempts.clone();

        let redis = redis::Client::open("redis://127.0.0.1:6379").unwrap();
        let app_state = Arc::new(AppState {
            db: None,
            metrics_exporter: Arc::new(MetricsExporter::new()),
            error_manager: Arc::new(ErrorManager::new()),
            config_manager: Arc::new(ConfigManager::new(AppConfig::default())),
            log_aggregator: Arc::new(LogAggregator::new().0),
            contract_benchmark_service: Arc::new(ContractBenchmarkService::new()),
            redis: redis.clone(),
        });

        let app = Router::new()
            .route(
                IDEMPOTENCY_ROUTE,
                post(move || {
                    let attempts = attempts_for_handler.clone();
                    async move {
                        let count = attempts.fetch_add(1, Ordering::SeqCst) + 1;
                        if count == 1 {
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(json!({ "error": "first failure" })),
                            )
                                .into_response()
                        } else {
                            (StatusCode::OK, Json(json!({ "status": "success" }))).into_response()
                        }
                    }
                })
                .route_layer(middleware::from_fn_with_state(
                    app_state.clone(),
                    idempotency_middleware,
                )),
            )
            .with_state(app_state);

        let idempotency_key = format!("retry-after-fail-{}", Uuid::new_v4());
        let request = || {
            Request::builder()
                .method("POST")
                .uri(IDEMPOTENCY_ROUTE)
                .header("content-type", "application/json")
                .header("Idempotency-Key", idempotency_key.clone())
                .body(Body::from(r#"{"message":"hello"}"#))
                .unwrap()
        };

        let first = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);

        // Second request with same key should be able to acquire lock since first released it
        let second = app.oneshot(request()).await.unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }
}
