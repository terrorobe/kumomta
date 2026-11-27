//! SMTP diagnostics for local file loggers.
use super::{LogCommand, LogRecordParams, LoggerImpl, LOGGER};
use chrono::Utc;
use flume::Sender;
use kumo_log_types::smtp::{SmtpConnectionEvent, SmtpConnectionRecord, SmtpDispositionFields};
use kumo_log_types::{RecordType, ResolvedAddress};
use kumo_prometheus::declare_metric;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

declare_metric! {
/// SMTP connection records discarded because the local file logger queue was full or closed.
static CONNECTION_DROPPED: IntCounterVec("log_smtp_connection_dropped_total", &["logger"]);
}

pub(super) fn validate_config(
    per_record: &HashMap<RecordType, LogRecordParams>,
    local: bool,
) -> anyhow::Result<()> {
    for (kind, params) in per_record {
        if *kind == RecordType::SmtpConnection {
            anyhow::ensure!(
                local,
                "SmtpConnection is only available in configure_local_logs"
            );
        } else {
            anyhow::ensure!(
                params.slow_threshold.is_none(),
                "slow_threshold is only supported for SmtpConnection"
            );
        }
    }
    Ok(())
}

pub(super) struct ConnectionLog {
    slow_threshold: Option<Duration>,
}

impl ConnectionLog {
    // Never fall back to Any, either at submission or at the file writer.
    pub(super) fn configured(per_record: &HashMap<RecordType, LogRecordParams>) -> Option<Self> {
        let params = per_record.get(&RecordType::SmtpConnection)?;
        params.enable.then_some(Self {
            slow_threshold: params.slow_threshold,
        })
    }

    fn should_log(&self, notable: bool, elapsed: Option<Duration>) -> bool {
        notable
            || elapsed
                .zip(self.slow_threshold)
                .is_some_and(|(d, min)| d >= min)
    }
}

/// Emit one message-independent record to each interested local file logger.
pub(crate) fn log_smtp_connection(
    session_id: Uuid,
    egress_source: &str,
    event: SmtpConnectionEvent,
    notable: bool,
    elapsed: Option<Duration>,
) {
    let loggers: Vec<_> = LOGGER
        .lock()
        .iter()
        .filter(|logger| {
            logger
                .connection_log
                .as_ref()
                .is_some_and(|selection| selection.should_log(notable, elapsed))
        })
        .cloned()
        .collect();
    if loggers.is_empty() {
        return;
    }
    let record = Arc::new(SmtpConnectionRecord::new(
        Utc::now(),
        session_id,
        egress_source,
        event,
    ));
    for logger in loggers {
        if let LoggerImpl::Queue { sender, .. } = &logger.implementation {
            let _timer = logger.submit_latency.start_timer();
            try_submit_connection(sender, &logger.name, Arc::clone(&record));
        }
    }
}

fn try_submit_connection(
    sender: &Sender<LogCommand>,
    logger: &str,
    record: Arc<SmtpConnectionRecord>,
) {
    if sender.try_send(LogCommand::SmtpConnection(record)).is_err() {
        CONNECTION_DROPPED.with_label_values(&[logger]).inc();
    }
}

pub(super) fn prepare_disposition(
    kind: RecordType,
    mut fields: SmtpDispositionFields,
) -> Option<SmtpDispositionFields> {
    match kind {
        RecordType::Delivery | RecordType::Bounce | RecordType::TransientFailure => {
            fields.clear_non_peer_response();
            Some(fields)
        }
        _ => None,
    }
}

pub(super) fn disposition_for_logger<'a>(
    hook_name: Option<&str>,
    native_peer: Option<&'a ResolvedAddress>,
    fields: Option<&'a SmtpDispositionFields>,
    saved_peer: Option<&'a ResolvedAddress>,
) -> (
    Option<&'a ResolvedAddress>,
    Option<&'a SmtpDispositionFields>,
) {
    // Both queued and immediate hooks are named; only local file loggers are unnamed.
    match (hook_name, fields) {
        (None, Some(_)) => (saved_peer.or(native_peer), fields),
        _ => (native_peer, None),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    #[test]
    fn connection_records_require_explicit_local_opt_in() {
        for config in [
            json!({}),
            json!({"Any": {"enable": true}}),
            json!({"Any": {"enable": true}, "SmtpConnection": {"enable": false}}),
        ] {
            let params = serde_json::from_value(config).unwrap();
            validate_config(&params, true).unwrap();
            assert!(ConnectionLog::configured(&params).is_none());
        }
        let params = serde_json::from_value(json!({"SmtpConnection": {}})).unwrap();
        assert!(validate_config(&params, false).is_err());
        validate_config(&params, true).unwrap();
        let selection = ConnectionLog::configured(&params).unwrap();
        assert!(selection.should_log(true, None));
        assert!(!selection.should_log(false, Some(Duration::from_secs(10))));
        let invalid = serde_json::from_value(json!({"Any": {"slow_threshold": "1s"}})).unwrap();
        assert!(validate_config(&invalid, true).is_err());
    }

    #[test]
    fn slow_threshold_is_inclusive_and_requires_a_measured_duration() {
        let params =
            serde_json::from_value(json!({"SmtpConnection": {"slow_threshold": "2s"}})).unwrap();
        validate_config(&params, true).unwrap();
        let selection = ConnectionLog::configured(&params).unwrap();
        assert!(selection.should_log(false, Some(Duration::from_secs(2))));
        assert!(!selection.should_log(false, Some(Duration::from_secs(1))));
        assert!(!selection.should_log(false, None));
        assert!(selection.should_log(true, None));
    }

    #[test]
    fn full_logger_drops_connection_record_without_waiting() {
        let (sender, receiver) = flume::bounded(1);
        sender.try_send(LogCommand::Terminate).unwrap();
        let logger = "dir-test-full-connection-queue";
        let dropped = CONNECTION_DROPPED.with_label_values(&[logger]);
        let before = dropped.get();
        let record = SmtpConnectionRecord::new(
            Utc::now(),
            Uuid::nil(),
            "test",
            SmtpConnectionEvent::AddressList {
                outcome: "no_address".into(),
                usable_ip_candidates: 0,
                address_list_build_ms: None,
            },
        );

        let (done, finished) = flume::bounded(1);
        std::thread::scope(|scope| {
            scope.spawn(move || {
                try_submit_connection(&sender, logger, Arc::new(record));
                done.send(()).unwrap();
            });
            // Keep the queue full until submission returns. On timeout, release a blocked sender.
            let result = finished.recv_timeout(Duration::from_secs(5));
            drop(receiver);
            result.expect("SMTP connection logging waited for queue capacity");
        });
        assert_eq!(dropped.get(), before + 1);
    }

    #[test]
    fn saved_transaction_peer_and_smtp_fields_are_local_only() {
        let peer = ResolvedAddress {
            name: "mx.example".into(),
            addr: std::net::Ipv4Addr::new(192, 0, 2, 1).into(),
            is_secure: false,
        };
        let error = serde_json::from_value(json!({
            "transaction_number": 7, "failure_kind": "local_error", "smtp_stage": "data_dot",
            "peer_response": {"code": 421}
        }))
        .unwrap();
        let fields = prepare_disposition(RecordType::TransientFailure, error).unwrap();
        assert_eq!(fields.transaction_number, Some(7));
        assert!(fields.peer_response.is_none());
        let peer = Some(&peer);
        for (native, saved) in [(None, peer), (peer, None)] {
            assert_eq!(
                disposition_for_logger(None, native, Some(&fields), saved),
                (peer, Some(&fields))
            );
            assert_eq!(
                disposition_for_logger(Some("hook"), native, Some(&fields), saved),
                (native, None)
            );
            assert_eq!(
                disposition_for_logger(None, native, None, saved),
                (native, None)
            );
        }
        assert!(prepare_disposition(RecordType::Reception, fields).is_none());
    }
}
