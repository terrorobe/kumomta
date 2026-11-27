use super::*;
use serde_json::json;

fn connection_record() -> Arc<smtp::SmtpConnectionRecord> {
    serde_json::from_value(json!({
        "type": "SmtpConnection", "timestamp": 0, "session_id": uuid::Uuid::nil(),
        "egress_source": "private-connection-source", "event": "address_list",
        "outcome": "no_address", "usable_ip_candidates": 0
    }))
    .unwrap()
}

fn set_template(
    state: &mut LogThreadState,
    kind: RecordType,
    template: &str,
    suffix: Option<&str>,
) {
    state.params.per_record.insert(
        kind,
        serde_json::from_value(json!({"template":template, "suffix":suffix})).unwrap(),
    );
    state
        .template_engine
        .add_template(format!("{kind:?}"), template)
        .unwrap();
}

#[test]
fn connection_record_only_uses_its_explicit_local_template() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = state(dir.path().to_path_buf(), 4096);
    let record = connection_record();
    set_template(&mut state, RecordType::Any, "should not render", None);
    state.do_smtp_connection(record.clone()).unwrap();
    assert_eq!(segment_count(dir.path()), 0);
    set_template(
        &mut state,
        RecordType::SmtpConnection,
        "{{ type }}:{{ event }}:{{ log_record.outcome }}",
        Some(".smtp"),
    );
    state.do_smtp_connection(record).unwrap();
    let path = state.file_map.values().next().unwrap().name.clone();
    state.file_map.clear();
    assert_eq!(path.extension().unwrap(), "smtp");
    let text = zstd::stream::decode_all(std::fs::File::open(path).unwrap()).unwrap();
    assert_eq!(text.as_slice(), b"SmtpConnection:address_list:no_address\n");
}

#[test]
fn only_unenriched_file_records_appear_in_traces() {
    use tracing::{span, Event, Metadata, Subscriber};

    #[derive(Default)]
    struct Capture(parking_lot::Mutex<String>);
    impl Subscriber for Capture {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }
        fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
        fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
        fn enter(&self, _: &span::Id) {}
        fn exit(&self, _: &span::Id) {}
        fn event(&self, event: &Event<'_>) {
            self.0.lock().push_str(&format!("{event:?}\n"));
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let mut state = state(dir.path().to_path_buf(), 4096);
    // A missing include can put the requested template name in the error.
    let template = "{% include egress_source or recipient %}";
    for kind in [RecordType::Delivery, RecordType::SmtpConnection] {
        set_template(&mut state, kind, template, None);
    }
    let trace = Arc::new(Capture::default());
    tracing::subscriber::with_default(trace.clone(), || {
        state.do_record(record("ordinary@example.com")).unwrap();
        let mut enriched = record("private-recipient@example.com");
        enriched.kind = RecordType::Delivery;
        enriched.smtp = Some(Box::new(smtp::SmtpDispositionFields {
            transaction_number: Some(1),
            ..Default::default()
        }));
        let err = state.do_record(enriched).unwrap_err();
        assert_eq!(format!("{err:#}"), "failed to render Delivery template");
        let err = state.do_smtp_connection(connection_record()).unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            "failed to render SmtpConnection template"
        );
    });
    let text = trace.0.lock();
    assert!(text.contains("ordinary@example.com"));
    assert!(text.contains("writing Delivery record"));
    assert!(text.contains("writing SmtpConnection record"));
    assert!(!text.contains("private-recipient@example.com"));
    assert!(!text.contains("private-connection-source"));
}
