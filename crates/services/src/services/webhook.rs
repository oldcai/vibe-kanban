use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::Serialize;
use sha2::Sha256;
use uuid::Uuid;

use db::models::task::TaskStatus;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize)]
struct TaskSyncPayload {
    #[serde(rename = "eventId")]
    event_id: String,
    #[serde(rename = "type")]
    event_type: String,
    timestamp: String,
    data: TaskSyncData,
}

#[derive(Debug, Serialize)]
struct TaskSyncData {
    #[serde(rename = "issueKey")]
    issue_key: String,
    #[serde(rename = "taskId")]
    task_id: String,
    status: String,
    summary: String,
}

fn map_status(status: &TaskStatus) -> Option<&'static str> {
    match status {
        TaskStatus::InReview => Some("in_review"),
        TaskStatus::Done => Some("completed"),
        TaskStatus::Cancelled => Some("failed"),
        // InProgress and Todo don't need webhook (Forge handles on launch)
        _ => None,
    }
}

fn sign_payload(body: &str, secret: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Dispatch a webhook notification for a task status change.
///
/// Fires a signed `task.sync.v1` event to `webhook_url` when `new_status` maps
/// to a reportable state (`InReview`, `Done`, or `Cancelled`). No-ops silently
/// for other statuses so callers can invoke this unconditionally on every update.
pub async fn dispatch_task_status_webhook(
    webhook_url: &str,
    webhook_secret: &str,
    task_id: Uuid,
    external_id: &str,
    new_status: &TaskStatus,
    task_title: &str,
) {
    let Some(sync_status) = map_status(new_status) else {
        return; // Status doesn't need a webhook notification
    };

    let payload = TaskSyncPayload {
        event_id: format!("vk-{}-{}", task_id, Utc::now().timestamp_millis()),
        event_type: "task.sync.v1".to_string(),
        timestamp: Utc::now().to_rfc3339(),
        data: TaskSyncData {
            issue_key: external_id.to_string(),
            task_id: task_id.to_string(),
            status: sync_status.to_string(),
            summary: format!("Task '{}' status changed to {}", task_title, new_status),
        },
    };

    let body = match serde_json::to_string(&payload) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Failed to serialize webhook payload: {}", e);
            return;
        }
    };

    let signature = sign_payload(&body, webhook_secret);

    let client = Client::new();
    match client
        .post(webhook_url)
        .header("Content-Type", "application/json")
        .header("x-vk-signature", signature)
        .body(body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(resp) => {
            tracing::info!(
                "Webhook dispatched for task {} ({}): HTTP {}",
                task_id,
                external_id,
                resp.status()
            );
        }
        Err(e) => {
            tracing::warn!(
                "Webhook dispatch failed for task {} ({}): {}",
                task_id,
                external_id,
                e
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_status_in_review() {
        assert_eq!(map_status(&TaskStatus::InReview), Some("in_review"));
    }

    #[test]
    fn test_map_status_done() {
        assert_eq!(map_status(&TaskStatus::Done), Some("completed"));
    }

    #[test]
    fn test_map_status_cancelled() {
        assert_eq!(map_status(&TaskStatus::Cancelled), Some("failed"));
    }

    #[test]
    fn test_map_status_todo_is_none() {
        assert_eq!(map_status(&TaskStatus::Todo), None);
    }

    #[test]
    fn test_map_status_in_progress_is_none() {
        assert_eq!(map_status(&TaskStatus::InProgress), None);
    }

    #[test]
    fn test_sign_payload_is_deterministic() {
        let sig1 = sign_payload("hello world", "secret");
        let sig2 = sign_payload("hello world", "secret");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_sign_payload_differs_with_different_secret() {
        let sig1 = sign_payload("hello world", "secret1");
        let sig2 = sign_payload("hello world", "secret2");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_sign_payload_is_hex_string() {
        let sig = sign_payload("test", "key");
        // HMAC-SHA256 produces 32 bytes = 64 hex chars
        assert_eq!(sig.len(), 64);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
