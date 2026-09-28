use crate::kumod::{DaemonWithMaildirOptions, MailGenParams};
use anyhow::Context;
use kumo_log_types::RecordType::{Delivery, TransientFailure};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rfc5321::SmtpClient;
use std::path::Path;
use std::time::Duration;

/// End-to-end coverage for the MTA-STS aliasing fix (#484): a domain whose
/// enforce-mode policy permits none of its MX hosts must fail to resolve with a
/// transient error, rather than silently affecting co-sited siblings. The
/// policy is supplied via `kumo.dns.configure_test_mta_sts`, so no live DNS or
/// HTTPS policy endpoint is involved.
#[tokio::test]
async fn mta_sts_enforce_impossible() -> anyhow::Result<()> {
    let mut daemon = DaemonWithMaildirOptions::new()
        .policy_file("mta-sts.lua")
        .start()
        .await
        .context("DaemonWithMaildir::start")?;

    let mut client = daemon.smtp_client().await.context("make smtp_client")?;

    let response = MailGenParams {
        recip: Some("victim@broken.example.com"),
        ..Default::default()
    }
    .send(&mut client)
    .await
    .context("send message")?;
    anyhow::ensure!(response.code == 250);

    daemon
        .wait_for_source_summary(
            |summary| summary.get(&TransientFailure).copied().unwrap_or(0) > 0,
            Duration::from_secs(50),
        )
        .await;

    daemon.stop_both().await.context("stop_both")?;

    let records = daemon.source.collect_logs().await?;
    let failure = records
        .iter()
        .find(|r| r.kind == TransientFailure)
        .context("expected a TransientFailure record")?;

    let normalized = mod_smtp_response_normalize::normalize(&failure.response.to_single_line());
    k9::snapshot!(
        normalized,
        r#"451 4.4.4 failed to resolve queue broken.example.com: MTA-STS enforce policy for broken.example.com permits none of its MX hosts "mail.broken.example.com." allowed mx patterns: "allowed.example.net" The destination is undeliverable until its MTA-STS policy is corrected."#
    );

    Ok(())
}

/// Companion to [`mta_sts_enforce_impossible`]: an enforce-mode policy whose
/// allowed MX patterns cover the domain's MX host leaves resolution unchanged,
/// so delivery proceeds normally.
#[tokio::test]
async fn mta_sts_enforce_match() -> anyhow::Result<()> {
    let mut daemon = DaemonWithMaildirOptions::new()
        .policy_file("mta-sts.lua")
        .start()
        .await
        .context("DaemonWithMaildir::start")?;

    let mut client = daemon.smtp_client().await.context("make smtp_client")?;

    let response = MailGenParams {
        recip: Some("winner@good.example.com"),
        ..Default::default()
    }
    .send(&mut client)
    .await
    .context("send message")?;
    anyhow::ensure!(response.code == 250);

    daemon
        .wait_for_source_summary(
            |summary| summary.get(&Delivery).copied().unwrap_or(0) > 0,
            Duration::from_secs(50),
        )
        .await;

    daemon.stop_both().await.context("stop_both")?;

    let delivery_summary = daemon.dump_logs().await.context("dump_logs")?;
    k9::snapshot!(
        delivery_summary,
        "
DeliverySummary {
    source_counts: {
        Reception: 1,
        Delivery: 1,
    },
    sink_counts: {
        Reception: 1,
        Delivery: 1,
    },
}
"
    );

    Ok(())
}

/// An enforcing recipient must not inherit the weaker policy of a domain with
/// identical MX records. Both messages reach one source/MX ready queue.
async fn enforce_after_none(aggressive: bool, untrusted_tls: bool) -> anyhow::Result<()> {
    let mut options = DaemonWithMaildirOptions::new().policy_file("mta-sts.lua");
    if aggressive {
        options = options.env("KUMOD_AGGRESSIVE_MTA_STS", "1");
    }
    if untrusted_tls {
        options = options.env("KUMOD_UNTRUSTED_MTA_STS_TLS", "1");
    } else {
        options = options.env("KUMOD_HIDE_STARTTLS", "1");
    }
    let mut daemon = options.start().await?;
    let mut client = daemon.smtp_client().await?;

    for recipient in ["first@none.example.com", "second@enforce.example.com"] {
        let response = MailGenParams {
            recip: Some(recipient),
            ..Default::default()
        }
        .send(&mut client)
        .await?;
        anyhow::ensure!(response.code == 250, "{recipient}: {response:?}");
        if recipient == "first@none.example.com" {
            anyhow::ensure!(
                daemon
                    .wait_for_maildir_count(1, Duration::from_secs(50))
                    .await,
                "the first, mode=none message did not reach the no-STARTTLS sink"
            );
        }
    }

    anyhow::ensure!(
        daemon
            .wait_for_source_summary(
                |summary| summary.get(&TransientFailure).copied().unwrap_or(0) > 0
                    || summary.get(&Delivery).copied().unwrap_or(0) > 1,
                Duration::from_secs(50),
            )
            .await,
        "no outbound result for enforce.example.com"
    );
    daemon.stop_both().await?;

    let records = daemon.source.collect_logs().await?;
    let first_delivery = records.iter().find(|r| {
        r.kind == Delivery
            && r.recipient
                .iter()
                .any(|addr| addr == "first@none.example.com")
    });
    anyhow::ensure!(
        first_delivery.is_some_and(|r| r.tls_cipher.is_some() == untrusted_tls),
        "first message used unexpected TLS transport: {first_delivery:?}"
    );
    let result: Vec<_> = records
        .iter()
        .filter(|r| {
            r.recipient
                .iter()
                .any(|addr| addr == "second@enforce.example.com")
                && matches!(r.kind, Delivery | TransientFailure)
        })
        .map(|r| (r.kind, r.tls_cipher.as_deref()))
        .collect();
    anyhow::ensure!(
        result.iter().any(|(kind, _)| *kind == TransientFailure)
            && !result.iter().any(|(kind, _)| *kind == Delivery),
        "enforce mail must defer without STARTTLS, observed {result:?}"
    );
    anyhow::ensure!(
        daemon.extract_maildir_messages()?.len() == 1,
        "the enforce recipient reached the no-STARTTLS sink"
    );
    Ok(())
}

#[tokio::test]
async fn mta_sts_enforce_shared_mx_after_none() -> anyhow::Result<()> {
    enforce_after_none(false, false).await
}

#[tokio::test]
async fn mta_sts_enforce_shared_mx_aggressive_opening() -> anyhow::Result<()> {
    enforce_after_none(true, false).await
}

#[tokio::test]
async fn mta_sts_enforce_shared_mx_after_untrusted_tls() -> anyhow::Result<()> {
    enforce_after_none(false, true).await
}

fn trusted_sink(names: &[&str]) -> anyhow::Result<(tempfile::TempDir, DaemonWithMaildirOptions)> {
    let mut ca_params = CertificateParams::default();
    let mut ca_name = DistinguishedName::new();
    ca_name.push(DnType::CommonName, "Kumo test CA");
    ca_params.distinguished_name = ca_name;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate()?)?;
    let mut server_params = CertificateParams::new(
        names
            .iter()
            .map(|name| name.to_string())
            .collect::<Vec<_>>(),
    )?;
    let mut server_name = DistinguishedName::new();
    server_name.push(DnType::CommonName, names[0]);
    server_params.distinguished_name = server_name;
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate()?;
    let server = server_params.signed_by(&server_key, &ca)?;
    let dir = tempfile::tempdir()?;
    let ca_file = dir.path().join("ca.pem");
    std::fs::write(&ca_file, ca.pem())?;

    let options = DaemonWithMaildirOptions::new()
        .policy_file("mta-sts.lua")
        .env("SSL_CERT_FILE", ca_file.display().to_string())
        .env("KUMOD_SINK_TLS_CERT", server.pem())
        .env("KUMOD_SINK_TLS_KEY", server_key.serialize_pem());
    Ok((dir, options))
}

async fn reuse_validated_session(backend: &str, dane: bool) -> anyhow::Result<()> {
    // The DANE certificate deliberately fails PKIX hostname validation.
    let name = if dane {
        "not-the-mx.example.com"
    } else {
        "mail.shared.example.com"
    };
    let (_ca, mut options) = trusted_sink(&[name])?;
    options = options.env("KUMOD_MTA_STS_TLS_BACKEND", backend);
    if dane {
        options = options.env("KUMOD_MTA_STS_DANE", "1");
    }
    let mut daemon = options.start().await?;
    let mut client = daemon.smtp_client().await?;
    let recipients = if dane {
        ["first@enforce.example.com", "second@enforce.example.com"]
    } else {
        ["first@none.example.com", "second@enforce.example.com"]
    };
    for (index, recipient) in recipients.into_iter().enumerate() {
        let response = MailGenParams {
            recip: Some(recipient),
            ..Default::default()
        }
        .send(&mut client)
        .await?;
        anyhow::ensure!(response.code == 250);
        anyhow::ensure!(
            daemon
                .wait_for_maildir_count(index + 1, Duration::from_secs(10))
                .await,
            "{recipient} did not deliver over trusted TLS"
        );
    }
    daemon.stop_both().await?;
    let records = daemon.source.collect_logs().await?;
    let deliveries: Vec<_> = records.iter().filter(|r| r.kind == Delivery).collect();
    anyhow::ensure!(deliveries.len() == 2, "unexpected results: {records:?}");
    anyhow::ensure!(deliveries.iter().all(|r| r.tls_cipher.is_some()));
    // A dispatcher session can span reconnections; the sink's reception
    // session IDs identify actual TCP connections.
    let records = daemon.sink.collect_logs().await?;
    let receptions: Vec<_> = records
        .iter()
        .filter(|r| r.kind == kumo_log_types::RecordType::Reception)
        .collect();
    anyhow::ensure!(receptions.len() == 2);
    anyhow::ensure!(
        receptions[0].session_id.is_some() && receptions[0].session_id == receptions[1].session_id,
        "validated connection was not reused: {receptions:?}"
    );
    Ok(())
}

#[tokio::test]
async fn mta_sts_reuses_pkix_validated_shared_mx() -> anyhow::Result<()> {
    reuse_validated_session("openssl", false).await
}

// rustls uses the system keychain on macOS rather than SSL_CERT_FILE.
// Linux can trust the fixture CA without changing the host trust store.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn mta_sts_reuses_pkix_validated_shared_mx_rustls() -> anyhow::Result<()> {
    reuse_validated_session("rustls", false).await
}

#[tokio::test]
async fn mta_sts_reuses_dane_same_domain() -> anyhow::Result<()> {
    reuse_validated_session("openssl", true).await
}

#[tokio::test]
async fn mta_sts_none_shared_mx_after_enforce() -> anyhow::Result<()> {
    let mut daemon = DaemonWithMaildirOptions::new()
        .policy_file("mta-sts.lua")
        .env("KUMOD_HIDE_STARTTLS", "1")
        .start()
        .await?;
    let mut client = daemon.smtp_client().await?;
    let first = MailGenParams {
        recip: Some("first@enforce.example.com"),
        ..Default::default()
    }
    .send(&mut client)
    .await?;
    anyhow::ensure!(first.code == 250);
    anyhow::ensure!(
        daemon
            .wait_for_source_summary(
                |summary| summary.get(&TransientFailure).copied().unwrap_or(0) > 0,
                Duration::from_secs(50),
            )
            .await,
        "the enforcing recipient did not defer without STARTTLS"
    );

    let second = MailGenParams {
        recip: Some("second@none.example.com"),
        ..Default::default()
    }
    .send(&mut client)
    .await?;
    anyhow::ensure!(second.code == 250);
    anyhow::ensure!(
        daemon
            .wait_for_maildir_count(1, Duration::from_secs(50))
            .await,
        "mode=none mail must deliver even after enforce created the shared queue"
    );
    daemon.stop_both().await?;
    let records = daemon.source.collect_logs().await?;
    let delivery = records.iter().find(|r| {
        r.kind == Delivery
            && r.recipient
                .iter()
                .any(|addr| addr == "second@none.example.com")
    });
    anyhow::ensure!(
        delivery.is_some_and(|r| r.tls_cipher.is_none()),
        "mode=none mail did not deliver without STARTTLS: {delivery:?}"
    );
    Ok(())
}

/// A queued message must be re-promoted when refreshed MTA-STS policy prunes
/// its former MX set to a different site.
#[tokio::test]
async fn mta_sts_policy_change_repromotes_site() -> anyhow::Result<()> {
    let mut daemon = DaemonWithMaildirOptions::new()
        .policy_file("mta-sts.lua")
        .env("KUMOD_TRANSITION_STS", "1")
        .env("KUMOD_HIDE_STARTTLS", "1")
        .start()
        .await?;
    let mut client = daemon.smtp_client().await?;
    let response = MailGenParams {
        recip: Some("recip@transition.example.com"),
        ..Default::default()
    }
    .send(&mut client)
    .await?;
    anyhow::ensure!(response.code == 250);
    anyhow::ensure!(
        daemon
            .wait_for_source_summary(
                |summary| summary.get(&TransientFailure).copied().unwrap_or(0) > 0,
                Duration::from_secs(10),
            )
            .await,
        "transition mail did not defer after its enforce policy was applied"
    );
    daemon.stop_both().await?;
    let records = daemon.source.collect_logs().await?;
    let failure = records.iter().find(|r| {
        r.kind == TransientFailure
            && r.recipient
                .iter()
                .any(|addr| addr == "recip@transition.example.com")
    });
    anyhow::ensure!(
        failure.is_some_and(|r| r.site == "unspecified->mail.other.example.com@smtp_client"),
        "message was not re-promoted under the newly permitted MX: {failure:?}"
    );
    anyhow::ensure!(daemon.extract_maildir_messages()?.is_empty());
    Ok(())
}

async fn send(client: &mut SmtpClient, recipient: &str) -> anyhow::Result<()> {
    let response = MailGenParams {
        recip: Some(recipient),
        ..Default::default()
    }
    .send(client)
    .await?;
    anyhow::ensure!(response.code == 250, "{recipient}: {response:?}");
    Ok(())
}

async fn wait_file(path: &Path) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .with_context(|| format!("waiting for {}", path.display()))
}

async fn update_policy(control: &Path, domain: &str, policy: &str) -> anyhow::Result<()> {
    let ack = control.join("applied");
    if ack.exists() {
        std::fs::remove_file(&ack)?;
    }
    let temporary = control.join("policies.tmp");
    std::fs::write(
        &temporary,
        serde_json::to_vec(&serde_json::json!({domain: policy}))?,
    )?;
    std::fs::rename(temporary, control.join("policies.json"))?;
    wait_file(&ack).await
}

async fn reject_wrong_hostname(backend: &str) -> anyhow::Result<()> {
    let (_ca, options) = trusted_sink(&["not-the-mx.example.com"])?;
    let mut daemon = options
        .env("KUMOD_MTA_STS_TLS_BACKEND", backend)
        .env("KUMOD_UNTRUSTED_MTA_STS_TLS", "1")
        .start()
        .await?;
    let mut client = daemon.smtp_client().await?;
    send(&mut client, "first@none.example.com").await?;
    anyhow::ensure!(
        daemon
            .wait_for_maildir_count(1, Duration::from_secs(10))
            .await
    );
    send(&mut client, "second@enforce.example.com").await?;
    anyhow::ensure!(
        daemon
            .wait_for_source_summary(
                |s| s.get(&TransientFailure).copied().unwrap_or(0) > 0,
                Duration::from_secs(10)
            )
            .await
    );
    daemon.stop_both().await?;
    let records = daemon.source.collect_logs().await?;
    let failure = records
        .iter()
        .find(|r| r.kind == TransientFailure)
        .context("expected hostname-validation failure")?;
    let expected_error = if backend == "rustls" {
        "certificate not valid for name"
    } else {
        "certificate verify failed"
    };
    anyhow::ensure!(
        failure.response.content.contains(expected_error),
        "{failure:?}"
    );
    anyhow::ensure!(records.iter().filter(|r| r.kind == Delivery).count() == 1);
    anyhow::ensure!(daemon.extract_maildir_messages()?.len() == 1);
    Ok(())
}

#[tokio::test]
async fn mta_sts_rejects_trusted_wrong_hostname() -> anyhow::Result<()> {
    reject_wrong_hostname("openssl").await
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn mta_sts_rejects_trusted_wrong_hostname_rustls() -> anyhow::Result<()> {
    reject_wrong_hostname("rustls").await
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum QueuedPolicyChange {
    RequireTls,
    RequirePkix,
    ExpirePolicy,
    ChangeSite,
}

/// Keep one delivery in DATA while other messages accumulate on its ready
/// queue. Policy updates then exercise the dispatcher, not just promotion.
async fn queued_policy_change(change: QueuedPolicyChange) -> anyhow::Result<()> {
    let control = tempfile::tempdir()?;
    let site_change = change == QueuedPolicyChange::ChangeSite;
    let delivers = site_change || change == QueuedPolicyChange::RequirePkix;
    let (_ca, mut options) = trusted_sink(&["mail.shared.example.com", "mail.other.example.com"])?;
    if delivers {
        // Leave the initial TLS connection unverified, so the moved message
        // must authenticate independently under its new enforcing policy.
        options = options.env("KUMOD_UNTRUSTED_MTA_STS_TLS", "1");
    } else {
        options = options.env("KUMOD_HIDE_STARTTLS", "1");
    }
    let mut daemon = options
        .env(
            "KUMOD_MTA_STS_CONTROL",
            control.path().display().to_string(),
        )
        .start()
        .await?;
    let mut client = daemon.smtp_client().await?;
    let (held, affected, sibling) = if site_change {
        (
            "held@unchanged.example.com",
            "second@transition.example.com",
            "third@unchanged.example.com",
        )
    } else {
        (
            "held@none.example.com",
            if change == QueuedPolicyChange::ExpirePolicy {
                "second@none.example.com"
            } else {
                "second@enforce.example.com"
            },
            "third@sibling.example.com",
        )
    };
    send(&mut client, held).await?;
    wait_file(&control.path().join("entered")).await?;
    send(&mut client, affected).await?;
    send(&mut client, sibling).await?;
    if matches!(
        change,
        QueuedPolicyChange::ExpirePolicy | QueuedPolicyChange::ChangeSite
    ) {
        let (domain, host) = if site_change {
            ("transition.example.com", "mail.other.example.com")
        } else {
            ("none.example.com", "mail.shared.example.com")
        };
        update_policy(
            control.path(),
            domain,
            &format!("version: STSv1\nmode: enforce\nmx: {host}\nmax_age: 86400"),
        )
        .await?;
        // The initial policy snapshot expires after one second.
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    std::fs::write(control.path().join("release"), "")?;
    anyhow::ensure!(
        daemon
            .wait_for_maildir_count(if delivers { 3 } else { 2 }, Duration::from_secs(10))
            .await,
        "unrelated mail did not continue"
    );
    if !delivers {
        anyhow::ensure!(
            daemon
                .wait_for_source_summary(
                    |s| s.get(&TransientFailure).copied().unwrap_or(0) > 0,
                    Duration::from_secs(10)
                )
                .await
        );
    }
    std::fs::write(control.path().join("stop"), "")?;
    daemon.stop_both().await?;
    let records = daemon.source.collect_logs().await?;
    let sibling_delivery = records
        .iter()
        .find(|r| r.kind == Delivery && r.recipient.iter().any(|addr| addr == sibling))
        .context("sibling delivery")?;
    anyhow::ensure!(
        sibling_delivery.meta.get("promotions") == Some(&serde_json::json!(1)),
        "unrelated mail was re-promoted: {sibling_delivery:?}"
    );
    anyhow::ensure!(sibling_delivery.num_attempts == 0);
    let affected_result = records
        .iter()
        .find(|r| {
            r.recipient.iter().any(|addr| addr == affected)
                && matches!(r.kind, Delivery | TransientFailure)
        })
        .context("affected result")?;
    if site_change {
        anyhow::ensure!(
            affected_result.kind == Delivery
                && affected_result.tls_cipher.is_some()
                && affected_result.site == "unspecified->mail.other.example.com@smtp_client"
                && affected_result.num_attempts == 0
                && affected_result.meta.get("promotions") == Some(&serde_json::json!(2)),
            "{affected_result:?}"
        );
        let receptions = daemon.sink.collect_logs().await?;
        let session_for = |recipient: &str| {
            receptions
                .iter()
                .find(|r| {
                    r.kind == kumo_log_types::RecordType::Reception
                        && r.recipient.iter().any(|addr| addr == recipient)
                })
                .and_then(|r| r.session_id)
        };
        anyhow::ensure!(
            session_for(held).is_some() && session_for(held) == session_for(sibling),
            "site change closed the unrelated recipients' connection"
        );
        anyhow::ensure!(
            session_for(affected).is_some() && session_for(affected) != session_for(held)
        );
    } else if delivers {
        anyhow::ensure!(
            affected_result.kind == Delivery
                && affected_result.tls_cipher.is_some()
                && affected_result.num_attempts == 0
                && affected_result.meta.get("promotions") == Some(&serde_json::json!(1)),
            "{affected_result:?}"
        );
        let receptions = daemon.sink.collect_logs().await?;
        let session_for = |recipient: &str| {
            receptions
                .iter()
                .find(|r| {
                    r.kind == kumo_log_types::RecordType::Reception
                        && r.recipient.iter().any(|addr| addr == recipient)
                })
                .and_then(|r| r.session_id)
        };
        anyhow::ensure!(
            session_for(affected).is_some() && session_for(held) != session_for(affected),
            "unverified connection was reused for enforcing mail"
        );
        anyhow::ensure!(
            session_for(affected) == session_for(sibling),
            "verified connection was not reused for unrelated mail"
        );
    } else {
        anyhow::ensure!(
            affected_result.kind == TransientFailure
                && affected_result
                    .response
                    .content
                    .contains("STARTTLS is not advertised"),
            "{affected_result:?}"
        );
        anyhow::ensure!(!records
            .iter()
            .any(|r| r.kind == Delivery && r.recipient.iter().any(|addr| addr == affected)));
    }
    Ok(())
}

#[tokio::test]
async fn mta_sts_policy_reconnect_keeps_unrelated_mail_ready() -> anyhow::Result<()> {
    queued_policy_change(QueuedPolicyChange::RequireTls).await
}

#[tokio::test]
async fn mta_sts_active_connection_policy_expiry() -> anyhow::Result<()> {
    queued_policy_change(QueuedPolicyChange::ExpirePolicy).await
}

#[tokio::test]
async fn mta_sts_active_site_change_preserves_other_mail() -> anyhow::Result<()> {
    queued_policy_change(QueuedPolicyChange::ChangeSite).await
}

#[tokio::test]
async fn mta_sts_expired_impossible_policy_defers_and_recovers() -> anyhow::Result<()> {
    let control = tempfile::tempdir()?;
    let mut daemon = DaemonWithMaildirOptions::new()
        .policy_file("mta-sts.lua")
        .env(
            "KUMOD_MTA_STS_CONTROL",
            control.path().display().to_string(),
        )
        .env("KUMOD_TRANSITION_STS", "impossible")
        .env("KUMOD_HIDE_STARTTLS", "1")
        .start()
        .await?;
    let mut client = daemon.smtp_client().await?;
    // Expiry happens after this message's ready queue is resolved but before
    // connecting, with candidate addresses still available. It must defer,
    // not loop on those untouched candidates or stun an unrelated domain.
    send(&mut client, "victim@transition.example.com").await?;
    anyhow::ensure!(
        daemon
            .wait_for_source_summary(
                |s| s.get(&TransientFailure).copied().unwrap_or(0) > 0,
                Duration::from_secs(10)
            )
            .await,
        "lookup failure did not defer"
    );
    send(&mut client, "other@unchanged.example.com").await?;
    anyhow::ensure!(
        daemon
            .wait_for_maildir_count(1, Duration::from_secs(10))
            .await
    );
    update_policy(
        control.path(),
        "transition.example.com",
        "version: STSv1\nmode: none\nmax_age: 86400",
    )
    .await?;
    anyhow::ensure!(
        daemon
            .wait_for_maildir_count(2, Duration::from_secs(15))
            .await,
        "deferred message did not recover"
    );
    std::fs::write(control.path().join("stop"), "")?;
    daemon.stop_both().await?;
    let records = daemon.source.collect_logs().await?;
    let failure = records
        .iter()
        .find(|r| r.kind == TransientFailure)
        .context("missing deferral")?;
    anyhow::ensure!(
        failure
            .response
            .content
            .contains("failed to resolve message MX/policy")
            && failure
                .response
                .content
                .contains("permits none of its MX hosts"),
        "{failure:?}"
    );
    let other = records
        .iter()
        .find(|r| {
            r.kind == Delivery
                && r.recipient
                    .iter()
                    .any(|addr| addr == "other@unchanged.example.com")
        })
        .context("other domain delivery")?;
    anyhow::ensure!(other.num_attempts == 0);
    let recovered = records
        .iter()
        .find(|r| {
            r.kind == Delivery
                && r.recipient
                    .iter()
                    .any(|addr| addr == "victim@transition.example.com")
        })
        .context("recovered delivery")?;
    anyhow::ensure!(recovered.num_attempts > 0);
    Ok(())
}

#[tokio::test]
async fn mta_sts_policy_reconnect_validates_without_retrying_message() -> anyhow::Result<()> {
    queued_policy_change(QueuedPolicyChange::RequirePkix).await
}

#[tokio::test]
async fn mta_sts_dane_proof_is_not_pkix_proof() -> anyhow::Result<()> {
    let (_ca, options) = trusted_sink(&["not-the-mx.example.com"])?;
    let mut daemon = options.env("KUMOD_MTA_STS_DANE", "1").start().await?;
    let mut client = daemon.smtp_client().await?;
    send(&mut client, "first@enforce.example.com").await?;
    anyhow::ensure!(
        daemon
            .wait_for_maildir_count(1, Duration::from_secs(10))
            .await
    );
    // The second domain's MX is not DNSSEC-secure, so DANE cannot supersede
    // its MTA-STS requirement. The first domain's DANE proof is insufficient.
    send(&mut client, "second@pkix.example.com").await?;
    anyhow::ensure!(
        daemon
            .wait_for_source_summary(
                |s| s.get(&TransientFailure).copied().unwrap_or(0) > 0,
                Duration::from_secs(10)
            )
            .await
    );
    daemon.stop_both().await?;
    let records = daemon.source.collect_logs().await?;
    anyhow::ensure!(
        records.iter().any(|r| r.kind == TransientFailure
            && r.recipient
                .iter()
                .any(|addr| addr == "second@pkix.example.com")
            && r.response.content.contains("certificate verify failed")),
        "{records:?}"
    );
    anyhow::ensure!(daemon.extract_maildir_messages()?.len() == 1);
    Ok(())
}
