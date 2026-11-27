use super::*;
use serde_json::{json, Value as JsonValue};

fn policy(params: JsonValue) -> anyhow::Result<Policy> {
    Policy::try_from(serde_json::from_value::<Params>(params)?)
}

#[test]
fn matches_mx_hosts_on_dns_label_boundaries() {
    let p = policy(json!({"providers": {
        "base": ["Example.COM."], "gateway": ["*.mx.example.com"],
        "explicit": ["=relay.mx.example.com"]
    }}))
    .unwrap();
    for (host, expected) in [
        ("EXAMPLE.com.", "base"),
        ("mx.example.com", "base"),
        ("Mx2.MX.Example.COM.:2525", "gateway"),
        ("relay.mx.example.com", "explicit"),
        ("x.relay.mx.example.com", "gateway"),
        ("notexample.com", "other"),
        ("example.com.attacker.test", "other"),
        ("mx.example.com:70000", "other"),
        ("192.0.2.42", "other"),
        ("[::1]:25", "other"),
        (".", "unknown"),
    ] {
        assert_eq!(p.provider(host), expected, "{host}");
    }
    assert_eq!(p.plan_provider([].into_iter()), "unknown");
    assert_eq!(
        p.plan_provider(["a.example.com", "b.example.com"].into_iter()),
        "base"
    );
    assert_eq!(
        p.plan_provider(["a.mx.example.com", "b.example.com"].into_iter()),
        "other"
    );
    assert_eq!(p.plan_provider(["a.test", "b.test"].into_iter()), "other");
    assert_eq!(p.bounded_group("gateway"), "gateway");
    assert_eq!(p.bounded_group("unknown"), "unknown");
    assert_eq!(p.bounded_group("mx.example.com"), "other");
}

#[test]
fn rejects_ambiguous_rules_and_unbounded_labels() {
    for invalid in [
        json!({"providers": {"example.org": ["example.org"]}}),
        json!({"providers": {"unknown": ["example.org"]}}),
        json!({"providers": {"a": ["example.org"], "b": ["*.EXAMPLE.org."]}}),
        json!({"providers": {"a": ["127.0.0.1"]}}),
        json!({"providers": {"a": ["email@example.org"]}}),
        json!({"providers": {"a": vec!["example.org"; MAX_HOST_RULES + 1]}}),
        json!({"providers": (0..=MAX_PROVIDERS).map(|i| (format!("group{i}"), vec![format!("mx{i}.example")])).collect::<BTreeMap<_, _>>() }),
        json!({"reasons": ["bad label"]}),
        json!({"reasons": ["a".repeat(49)]}),
        json!({"reasons": vec!["reason"; MAX_REASONS + 1]}),
    ] {
        assert!(policy(invalid.clone()).is_err(), "{invalid}");
    }
}

#[test]
fn classifier_receives_no_command_or_sensitive_or_partial_text() {
    let mut response = Response {
        command: Some("RCPT TO:<private@example.invalid>".into()),
        ..Response::with_code_and_message(451, "4.7.1 retry later")
    };
    let input = classifier_input(SmtpStage::RcptTo, &response, false);
    assert_eq!(
        serde_json::to_value(input).unwrap(),
        json!({
            "code":451, "enhanced_code":{"class":4,"subject":7,"detail":1}, "content":"retry later"
        })
    );
    for stage in [
        SmtpStage::Auth,
        SmtpStage::DataWrite,
        SmtpStage::Pipeline,
        SmtpStage::Other,
    ] {
        let input = classifier_input(stage, &response, false);
        assert!(input.content.is_none());
    }
    assert!(classifier_input(SmtpStage::DataDot, &response, true)
        .content
        .is_none());
    response.content = "x".repeat(MAX_CLASSIFIER_INPUT + 1);
    assert!(classifier_input(SmtpStage::DataDot, &response, false)
        .content
        .is_none());
}

#[test]
fn classifier_output_is_typed_and_bounded() -> anyhow::Result<()> {
    let lua = Lua::new();
    let classify = |chunk: &str| lua.load(chunk).eval::<Classification>();
    let result = classify("return {reason='limited', content={ignored=true}}")?;
    assert_eq!(result.reason.as_deref(), Some("limited"));
    assert!(classify("return {reason=string.rep('x', 49)}")?
        .reason
        .is_none());
    for invalid in ["return 'peer text'", "return {reason={}}"] {
        assert!(classify(invalid).is_err(), "{invalid}");
    }
    Ok(())
}
