//! Delivers queued notifications (webhooks, Telegram) with retries.
//!
//! Notifications are written to the outbox in the same transaction as the
//! state change that caused them, so none is lost if the process stops.

use crate::http::{now, Shared};
use crate::service::OutboxItem;
use serde_json::json;
use std::time::Duration;
use twof_core::webhook;

fn agent() -> ureq::Agent {
    // No redirects: a webhook goes exactly where the operator pointed it.
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .redirects(0)
        .build()
}

fn deliver(service: &Shared, item: &OutboxItem, telegram_token: Option<&str>) -> bool {
    match item.kind.as_str() {
        "webhook" => agent()
            .post(&item.target)
            .set("Content-Type", "application/json")
            .set(
                webhook::SIGNATURE_HEADER,
                &webhook::sign(service.key(), item.body.as_bytes()),
            )
            .set(webhook::KEY_HEADER, &service.key().kid())
            .send_string(&item.body)
            .is_ok(),
        "telegram" => {
            let Some(token) = telegram_token else {
                return false;
            };
            let body = json!({ "chat_id": item.target, "text": item.body,
                               "disable_web_page_preview": true });
            agent()
                .post(&format!("https://api.telegram.org/bot{token}/sendMessage"))
                .set("Content-Type", "application/json")
                .send_string(&body.to_string())
                .is_ok()
        }
        _ => false,
    }
}

/// Sends everything that is due. Returns how many were delivered.
pub fn run_once(service: &Shared, telegram_token: Option<&str>) -> usize {
    let Ok(items) = service.outbox_due(now(), 20) else {
        return 0;
    };
    let mut delivered = 0;
    for item in items {
        let ok = deliver(service, &item, telegram_token);
        delivered += usize::from(ok);
        if let Err(e) = service.outbox_result(item.id, ok, now()) {
            eprintln!("outbox: {e:?}");
        }
    }
    delivered
}

/// Starts the delivery loop on its own thread.
pub fn spawn(service: Shared, telegram_token: Option<String>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || loop {
        run_once(&service, telegram_token.as_deref());
        std::thread::sleep(Duration::from_secs(1));
    })
}
