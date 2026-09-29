use crate::kumod::{DaemonWithMaildirOptions, MailGenParams};
use anyhow::Context;
use kumo_api_types::{TraceSmtpClientV1Payload, TraceSmtpV1Payload};
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

#[derive(Clone, Copy)]
enum TlsBackend {
    OpenSsl,
    #[cfg(target_os = "linux")]
    Rustls,
}

impl TlsBackend {
    fn as_env(self) -> &'static str {
        match self {
            Self::OpenSsl => "openssl",
            #[cfg(target_os = "linux")]
            Self::Rustls => "rustls",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaneMode {
    Matching,
    Mismatch,
    Unusable,
    Absent,
    ServFail,
    AddressAbsent,
}

impl DaneMode {
    fn as_env(self) -> &'static str {
        match self {
            Self::Matching => "matching",
            Self::Mismatch => "mismatch",
            Self::Unusable => "unusable",
            Self::Absent => "absent",
            Self::ServFail => "servfail",
            Self::AddressAbsent => "address_absent",
        }
    }
}

struct EnforceAfterNoneCase {
    aggressive: bool,
    untrusted_tls: bool,
}

struct SessionReuseCase {
    backend: TlsBackend,
    dane: Option<DaneMode>,
    route_port: bool,
}

struct DaneBypassCase {
    mta_sts_enabled: bool,
    secure_creator: bool,
}

struct DaneReuseCase {
    mode: DaneMode,
    mta_sts_enabled: bool,
    refresh: bool,
}

/// An enforcing recipient must not inherit the weaker policy of a domain with
/// identical MX records. Both messages reach one source/MX ready queue.
async fn enforce_after_none(case: EnforceAfterNoneCase) -> anyhow::Result<()> {
    let EnforceAfterNoneCase {
        aggressive,
        untrusted_tls,
    } = case;
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
    enforce_after_none(EnforceAfterNoneCase {
        aggressive: false,
        untrusted_tls: false,
    })
    .await
}

#[tokio::test]
async fn mta_sts_enforce_shared_mx_aggressive_opening() -> anyhow::Result<()> {
    enforce_after_none(EnforceAfterNoneCase {
        aggressive: true,
        untrusted_tls: false,
    })
    .await
}

#[tokio::test]
async fn mta_sts_enforce_shared_mx_after_untrusted_tls() -> anyhow::Result<()> {
    enforce_after_none(EnforceAfterNoneCase {
        aggressive: false,
        untrusted_tls: true,
    })
    .await
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

async fn reuse_validated_session(case: SessionReuseCase) -> anyhow::Result<()> {
    let SessionReuseCase {
        backend,
        dane,
        route_port,
    } = case;
    // The DANE certificate deliberately fails PKIX hostname validation.
    let name = if dane.is_some_and(|mode| mode != DaneMode::Absent) {
        "not-the-mx.example.com"
    } else {
        "mail.shared.example.com"
    };
    let (_ca, mut options) = trusted_sink(&[name])?;
    options = options.env("KUMOD_MTA_STS_TLS_BACKEND", backend.as_env());
    if let Some(mode) = dane {
        options = options
            .env("KUMOD_MTA_STS_DANE", mode.as_env())
            .env("KUMOD_MTA_STS_TLS", "Required");
    }
    if route_port {
        options = options.env("KUMOD_MTA_STS_ROUTE_PORT", "1");
    }
    let mut daemon = options.start().await?;
    let mut client = daemon.smtp_client().await?;
    let recipients = if dane.is_some() {
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
    reuse_validated_session(SessionReuseCase {
        backend: TlsBackend::OpenSsl,
        dane: None,
        route_port: false,
    })
    .await
}

// rustls uses the system keychain on macOS rather than SSL_CERT_FILE.
// Linux can trust the fixture CA without changing the host trust store.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn mta_sts_reuses_pkix_validated_shared_mx_rustls() -> anyhow::Result<()> {
    reuse_validated_session(SessionReuseCase {
        backend: TlsBackend::Rustls,
        dane: None,
        route_port: false,
    })
    .await
}

#[tokio::test]
async fn mta_sts_reuses_dane_same_domain() -> anyhow::Result<()> {
    reuse_validated_session(SessionReuseCase {
        backend: TlsBackend::OpenSsl,
        dane: Some(DaneMode::Matching),
        route_port: false,
    })
    .await
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

async fn reject_wrong_hostname(backend: TlsBackend) -> anyhow::Result<()> {
    let (_ca, options) = trusted_sink(&["not-the-mx.example.com"])?;
    let mut daemon = options
        .env("KUMOD_MTA_STS_TLS_BACKEND", backend.as_env())
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
    let expected_error = match backend {
        TlsBackend::OpenSsl => "certificate verify failed",
        #[cfg(target_os = "linux")]
        TlsBackend::Rustls => "certificate not valid for name",
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
    reject_wrong_hostname(TlsBackend::OpenSsl).await
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn mta_sts_rejects_trusted_wrong_hostname_rustls() -> anyhow::Result<()> {
    reject_wrong_hostname(TlsBackend::Rustls).await
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum QueuedPolicyChange {
    RequireTls,
    RequirePkix,
    ExpirePolicy,
    ChangeSite,
    EvictedSite,
}

/// Keep one delivery in DATA while other messages accumulate on its ready
/// queue. Policy updates then exercise the dispatcher, not just promotion.
async fn queued_policy_change(change: QueuedPolicyChange) -> anyhow::Result<()> {
    let control = tempfile::tempdir()?;
    let site_change = matches!(
        change,
        QueuedPolicyChange::ChangeSite | QueuedPolicyChange::EvictedSite
    );
    let delivers = site_change || change == QueuedPolicyChange::RequirePkix;
    let (_ca, mut options) = trusted_sink(&["mail.shared.example.com", "mail.other.example.com"])?;
    if change == QueuedPolicyChange::EvictedSite {
        options = options.env("KUMOD_MTA_STS_EVICT_MX", "1");
    }
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
        QueuedPolicyChange::ExpirePolicy
            | QueuedPolicyChange::ChangeSite
            | QueuedPolicyChange::EvictedSite
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
        if change != QueuedPolicyChange::EvictedSite {
            // The initial policy snapshot expires after one second.
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
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
    if delivers {
        anyhow::ensure!(
            affected_result.kind == Delivery
                && affected_result.tls_cipher.is_some()
                && affected_result.num_attempts == 0,
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
        if site_change {
            anyhow::ensure!(
                affected_result.site == "unspecified->mail.other.example.com@smtp_client"
                    && affected_result.meta.get("promotions") == Some(&serde_json::json!(2)),
                "{affected_result:?}"
            );
            anyhow::ensure!(
                session_for(held).is_some() && session_for(held) == session_for(sibling),
                "site change closed the unrelated recipients' connection"
            );
            anyhow::ensure!(
                session_for(affected).is_some() && session_for(affected) != session_for(held)
            );
        } else {
            anyhow::ensure!(
                affected_result.meta.get("promotions") == Some(&serde_json::json!(1)),
                "{affected_result:?}"
            );
            anyhow::ensure!(
                session_for(affected).is_some() && session_for(held) != session_for(affected),
                "unverified connection was reused for enforcing mail"
            );
            anyhow::ensure!(
                session_for(affected) == session_for(sibling),
                "verified connection was not reused for unrelated mail"
            );
        }
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
    let mut daemon = options
        .env("KUMOD_MTA_STS_DANE", DaneMode::Matching.as_env())
        .start()
        .await?;
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

#[tokio::test]
async fn mta_sts_reuses_pkix_port_qualified_route() -> anyhow::Result<()> {
    reuse_validated_session(SessionReuseCase {
        backend: TlsBackend::OpenSsl,
        dane: None,
        route_port: true,
    })
    .await
}

#[tokio::test]
async fn mta_sts_reuses_dane_unusable_same_domain() -> anyhow::Result<()> {
    reuse_validated_session(SessionReuseCase {
        backend: TlsBackend::OpenSsl,
        dane: Some(DaneMode::Unusable),
        route_port: false,
    })
    .await
}

#[tokio::test]
async fn mta_sts_reuses_pkix_when_dane_absent() -> anyhow::Result<()> {
    reuse_validated_session(SessionReuseCase {
        backend: TlsBackend::OpenSsl,
        dane: Some(DaneMode::Absent),
        route_port: false,
    })
    .await
}

async fn pkix_proof_does_not_bypass_dane(case: DaneBypassCase) -> anyhow::Result<()> {
    let DaneBypassCase {
        mta_sts_enabled,
        secure_creator,
    } = case;
    let (_ca, options) = trusted_sink(&["mail.shared.example.com"])?;
    let options = if !mta_sts_enabled {
        options.env("KUMOD_MTA_STS_NO_STS", "1")
    } else {
        options
    };
    let mut daemon = options
        .env("KUMOD_MTA_STS_DANE", DaneMode::Mismatch.as_env())
        .env("KUMOD_MTA_STS_NO_RETRY", "1")
        .start()
        .await?;
    let mut client = daemon.smtp_client().await?;
    // A PKIX session for an unsigned domain must not satisfy a secure domain's
    // DANE requirement, regardless of which domain creates the queue.
    if secure_creator {
        send(&mut client, "first@enforce.example.com").await?;
        anyhow::ensure!(
            daemon
                .wait_for_source_summary(
                    |s| s.get(&TransientFailure).copied().unwrap_or(0) > 0,
                    Duration::from_secs(10)
                )
                .await
        );
    }
    send(&mut client, "middle@pkix.example.com").await?;
    anyhow::ensure!(
        daemon
            .wait_for_maildir_count(1, Duration::from_secs(10))
            .await
    );
    send(&mut client, "last@enforce.example.com").await?;
    anyhow::ensure!(
        daemon
            .wait_for_source_summary(
                |s| s.get(&TransientFailure).copied().unwrap_or(0) > usize::from(secure_creator)
                    || s.get(&Delivery).copied().unwrap_or(0) > 1,
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
                .any(|addr| addr == "last@enforce.example.com")
            && r.response.content.contains("certificate verify failed")),
        "a PKIX session bypassed DANE: {records:?}"
    );
    anyhow::ensure!(daemon.extract_maildir_messages()?.len() == 1);
    Ok(())
}

#[tokio::test]
async fn mta_sts_pkix_proof_does_not_bypass_dane() -> anyhow::Result<()> {
    pkix_proof_does_not_bypass_dane(DaneBypassCase {
        mta_sts_enabled: true,
        secure_creator: true,
    })
    .await
}
#[tokio::test]
async fn mta_sts_disabled_pkix_proof_does_not_bypass_dane() -> anyhow::Result<()> {
    pkix_proof_does_not_bypass_dane(DaneBypassCase {
        mta_sts_enabled: false,
        secure_creator: true,
    })
    .await
}
#[tokio::test]
async fn mta_sts_dane_checks_unsigned_creator() -> anyhow::Result<()> {
    pkix_proof_does_not_bypass_dane(DaneBypassCase {
        mta_sts_enabled: true,
        secure_creator: false,
    })
    .await
}
#[tokio::test]
async fn mta_sts_disabled_dane_checks_unsigned_creator() -> anyhow::Result<()> {
    pkix_proof_does_not_bypass_dane(DaneBypassCase {
        mta_sts_enabled: false,
        secure_creator: false,
    })
    .await
}

async fn testing_then_none(tls: &str, hide_starttls: bool) -> anyhow::Result<()> {
    let mut options = DaemonWithMaildirOptions::new()
        .policy_file("mta-sts.lua")
        .env("KUMOD_MTA_STS_TLS", tls)
        .env("KUMOD_MTA_STS_NO_RETRY", "1");
    if hide_starttls {
        options = options.env("KUMOD_HIDE_STARTTLS", "1");
    }
    let mut daemon = options.start().await?;
    let mut client = daemon.smtp_client().await?;
    // none creates the queue with the configured floor; testing may weaken
    // its own connection but must not weaken the next none-domain message.
    send(&mut client, "first@none.example.com").await?;
    anyhow::ensure!(
        daemon
            .wait_for_source_summary(
                |s| s.get(&TransientFailure).copied().unwrap_or(0) > 0,
                Duration::from_secs(10)
            )
            .await
    );
    send(&mut client, "middle@testing.example.com").await?;
    anyhow::ensure!(
        daemon
            .wait_for_maildir_count(1, Duration::from_secs(10))
            .await
    );
    send(&mut client, "last@none.example.com").await?;
    anyhow::ensure!(
        daemon
            .wait_for_source_summary(
                |s| s.get(&TransientFailure).copied().unwrap_or(0) > 1
                    || s.get(&Delivery).copied().unwrap_or(0) > 1,
                Duration::from_secs(10)
            )
            .await
    );
    daemon.stop_both().await?;
    let records = daemon.source.collect_logs().await?;
    let result = records
        .iter()
        .find(|r| {
            matches!(r.kind, Delivery | TransientFailure)
                && r.recipient
                    .iter()
                    .any(|addr| addr == "last@none.example.com")
        })
        .context("missing final message result")?;
    anyhow::ensure!(
        result.kind == TransientFailure,
        "testing leaked into {tls}: {result:?}"
    );
    anyhow::ensure!(
        result.response.content.contains(if hide_starttls {
            "STARTTLS is not advertised"
        } else {
            "TLS handshake"
        }),
        "{result:?}"
    );
    anyhow::ensure!(daemon.extract_maildir_messages()?.len() == 1);
    Ok(())
}

#[tokio::test]
async fn mta_sts_testing_preserves_none_required() -> anyhow::Result<()> {
    testing_then_none("Required", true).await
}

#[tokio::test]
async fn mta_sts_testing_preserves_none_required_insecure() -> anyhow::Result<()> {
    testing_then_none("RequiredInsecure", true).await
}

#[tokio::test]
async fn mta_sts_testing_preserves_none_opportunistic_validation() -> anyhow::Result<()> {
    testing_then_none("Opportunistic", false).await
}

// A local policy switch does not itself reinsert the FIFO, but the replacement
// connection still observes site-wide connection limits and failure backoff.
async fn shared_queue_limits(limit: &str) -> anyhow::Result<()> {
    let control = tempfile::tempdir()?;
    let mut daemon = DaemonWithMaildirOptions::new()
        .policy_file("mta-sts.lua")
        .env(
            "KUMOD_MTA_STS_CONTROL",
            control.path().display().to_string(),
        )
        .env("KUMOD_MTA_STS_NO_RETRY", "1")
        .env("KUMOD_MTA_STS_LIMIT", limit)
        .env("KUMOD_HIDE_STARTTLS", "1")
        .start()
        .await?;
    let mut client = daemon.smtp_client().await?;
    send(&mut client, "held@none.example.com").await?;
    wait_file(&control.path().join("entered")).await?;
    send(&mut client, "second@enforce.example.com").await?;
    if limit == "backoff" {
        send(&mut client, "third@enforce.example.com").await?;
    }
    send(&mut client, "other@sibling.example.com").await?;
    std::fs::write(control.path().join("release"), "")?;
    // Rate throttling schedules a delay without logging a delivery failure.
    // Inspect scheduled state rather than requiring a TransientFailure record.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(queue) = daemon
                .source
                .api_client()
                .admin_inspect_sched_q_v1(&kumo_api_types::InspectQueueV1Request {
                    queue_name: "sibling.example.com".into(),
                    want_body: false,
                    limit: Some(0),
                })
                .await
            {
                if queue.num_scheduled == 1 {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .with_context(|| format!("shared {limit} was not applied"))?;
    std::fs::write(control.path().join("stop"), "")?;
    daemon.stop_both().await?;
    let records = daemon.source.collect_logs().await?;
    let other = records.iter().find(|r| {
        r.kind == TransientFailure
            && r.recipient
                .iter()
                .any(|addr| addr == "other@sibling.example.com")
    });
    if limit == "backoff" {
        anyhow::ensure!(
            other.is_some_and(|r| r.response.content.contains("bulk delay of ready queue")),
            "{other:?}"
        );
    } else {
        anyhow::ensure!(
            other.is_none(),
            "rate limiting must not count as a delivery failure: {other:?}"
        );
    }
    anyhow::ensure!(daemon.extract_maildir_messages()?.len() == 1);
    Ok(())
}

#[tokio::test]
async fn mta_sts_policy_reconnect_observes_shared_connection_rate() -> anyhow::Result<()> {
    shared_queue_limits("rate").await
}

#[tokio::test]
async fn mta_sts_policy_failures_observe_shared_backoff() -> anyhow::Result<()> {
    shared_queue_limits("backoff").await
}

#[tokio::test]
async fn mta_sts_site_change_after_cache_eviction() -> anyhow::Result<()> {
    queued_policy_change(QueuedPolicyChange::EvictedSite).await
}

#[tokio::test]
async fn mta_sts_none_disabled_to_testing_attempts_tls() -> anyhow::Result<()> {
    let mut daemon = DaemonWithMaildirOptions::new()
        .policy_file("mta-sts.lua")
        .env("KUMOD_MTA_STS_TLS", "Disabled")
        .start()
        .await?;
    let mut client = daemon.smtp_client().await?;
    send(&mut client, "first@none.example.com").await?;
    anyhow::ensure!(
        daemon
            .wait_for_maildir_count(1, Duration::from_secs(10))
            .await
    );
    send(&mut client, "second@testing.example.com").await?;
    anyhow::ensure!(
        daemon
            .wait_for_maildir_count(2, Duration::from_secs(10))
            .await
    );
    daemon.stop_both().await?;
    let records = daemon.source.collect_logs().await?;
    for (recipient, tls) in [
        ("first@none.example.com", false),
        ("second@testing.example.com", true),
    ] {
        anyhow::ensure!(
            records.iter().any(|r| r.kind == Delivery
                && r.recipient.iter().any(|addr| addr == recipient)
                && r.tls_cipher.is_some() == tls
                && r.num_attempts == 0),
            "{records:?}"
        );
    }
    Ok(())
}

async fn assert_same_sink_connection(
    daemon: &crate::kumod::DaemonWithMaildir,
) -> anyhow::Result<()> {
    let records = daemon.sink.collect_logs().await?;
    let sessions: Vec<_> = records
        .iter()
        .filter(|r| r.kind == kumo_log_types::RecordType::Reception)
        .map(|r| r.session_id)
        .collect();
    anyhow::ensure!(
        sessions.len() >= 2 && sessions[0].is_some() && sessions.iter().all(|s| s == &sessions[0]),
        "connection was not reused: {sessions:?}"
    );
    Ok(())
}

#[tokio::test]
async fn mta_sts_testing_preserves_plaintext_fallback() -> anyhow::Result<()> {
    let mut daemon = DaemonWithMaildirOptions::new()
        .policy_file("mta-sts.lua")
        .env("KUMOD_MTA_STS_FALLBACK", "1")
        .start()
        .await?;
    let mut client = daemon.smtp_client().await?;
    for (index, recipient) in ["first@none.example.com", "second@testing.example.com"]
        .into_iter()
        .enumerate()
    {
        send(&mut client, recipient).await?;
        anyhow::ensure!(
            daemon
                .wait_for_maildir_count(index + 1, Duration::from_secs(10))
                .await
        );
    }
    daemon.stop_both().await?;
    let records = daemon.source.collect_logs().await?;
    anyhow::ensure!(records
        .iter()
        .filter(|r| r.kind == Delivery)
        .all(|r| r.tls_cipher.is_none()));
    assert_same_sink_connection(&daemon).await
}

#[tokio::test]
async fn mta_sts_peer_close_precedes_policy_reconnect() -> anyhow::Result<()> {
    let (_ca, options) = trusted_sink(&["mail.shared.example.com", "mail.backup.example.com"])?;
    let mut daemon = options
        .env("KUMOD_MTA_STS_BACKUP", "1")
        .env("KUMOD_UNTRUSTED_MTA_STS_TLS", "1")
        .start()
        .await?;
    let trace = daemon.sink.trace_server().await?;
    let mut client = daemon.smtp_client().await?;
    send(&mut client, "first@none.example.com").await?;
    anyhow::ensure!(
        daemon
            .wait_for_maildir_count(1, Duration::from_secs(10))
            .await
    );
    // Observe the peer's actual 421 and closure. The source timeout is longer
    // than this wait, so it must retain the plan and apply reconnect_strategy.
    anyhow::ensure!(
        trace
            .wait_for(
                |events| {
                    events.iter().any(|event| {
                        matches!(&event.payload,
            TraceSmtpV1Payload::Write(line) if line.starts_with("421 "))
                    }) && events
                        .iter()
                        .any(|event| matches!(&event.payload, TraceSmtpV1Payload::Closed))
                },
                Duration::from_secs(10)
            )
            .await,
        "sink did not close the idle connection"
    );
    trace.stop().await?;
    send(&mut client, "second@enforce.example.com").await?;
    anyhow::ensure!(
        daemon
            .wait_for_maildir_count(2, Duration::from_secs(10))
            .await
    );
    daemon.stop_both().await?;
    let records = daemon.source.collect_logs().await?;
    for (recipient, host) in [
        ("first@none.example.com", "mail.shared.example.com."),
        ("second@enforce.example.com", "mail.backup.example.com."),
    ] {
        let record = records
            .iter()
            .find(|r| r.kind == Delivery && r.recipient.iter().any(|addr| addr == recipient))
            .context("delivery")?;
        anyhow::ensure!(
            record.peer_address.as_ref().is_some_and(|p| p.name == host)
                && record.num_attempts == 0,
            "reconnect strategy bypassed: {record:?}"
        );
    }
    Ok(())
}

async fn reuse_dane_across_domains(case: DaneReuseCase) -> anyhow::Result<()> {
    let DaneReuseCase {
        mode,
        mta_sts_enabled,
        refresh,
    } = case;
    let control = tempfile::tempdir()?;
    let (_ca, mut options) = trusted_sink(&[if mode == DaneMode::Absent {
        "mail.shared.example.com"
    } else {
        "not-the-mx.example.com"
    }])?;
    options = options
        .env("KUMOD_MTA_STS_DANE", mode.as_env())
        .env("KUMOD_MTA_STS_TLS", "Required");
    if !mta_sts_enabled {
        options = options.env("KUMOD_MTA_STS_NO_STS", "1");
    }
    if refresh {
        options = options
            .env("KUMOD_MTA_STS_SHORT_DANE_MX", "1")
            .env("KUMOD_SINK_CLIENT_TIMEOUT", "30s")
            .env(
                "KUMOD_MTA_STS_CONTROL",
                control.path().display().to_string(),
            );
    }
    let mut daemon = options.start().await?;
    let mut client = daemon.smtp_client().await?;
    for (index, recipient) in [
        "first@enforce.example.com",
        "second@secure.example.com",
        "third@enforce.example.com",
    ]
    .into_iter()
    .enumerate()
    {
        if refresh && index > 0 {
            update_dane(control.path(), mode).await?;
            tokio::time::sleep(Duration::from_millis(1100)).await;
        }
        send(&mut client, recipient).await?;
        anyhow::ensure!(
            daemon
                .wait_for_maildir_count(index + 1, Duration::from_secs(10))
                .await
        );
    }
    if refresh {
        std::fs::write(control.path().join("stop"), "")?;
    }
    daemon.stop_both().await?;
    assert_same_sink_connection(&daemon).await
}

#[tokio::test]
async fn mta_sts_dane_reuses_across_domains() -> anyhow::Result<()> {
    reuse_dane_across_domains(DaneReuseCase {
        mode: DaneMode::Matching,
        mta_sts_enabled: true,
        refresh: false,
    })
    .await
}
#[tokio::test]
async fn mta_sts_disabled_dane_reuses_across_domains() -> anyhow::Result<()> {
    reuse_dane_across_domains(DaneReuseCase {
        mode: DaneMode::Matching,
        mta_sts_enabled: false,
        refresh: false,
    })
    .await
}
#[tokio::test]
async fn mta_sts_dane_absence_reuses_across_domains() -> anyhow::Result<()> {
    reuse_dane_across_domains(DaneReuseCase {
        mode: DaneMode::Absent,
        mta_sts_enabled: true,
        refresh: false,
    })
    .await
}
#[tokio::test]
async fn mta_sts_dane_unusable_reuses_across_domains() -> anyhow::Result<()> {
    reuse_dane_across_domains(DaneReuseCase {
        mode: DaneMode::Unusable,
        mta_sts_enabled: true,
        refresh: false,
    })
    .await
}
#[tokio::test]
async fn mta_sts_dane_refresh_identical_records_reuses() -> anyhow::Result<()> {
    reuse_dane_across_domains(DaneReuseCase {
        mode: DaneMode::Matching,
        mta_sts_enabled: true,
        refresh: true,
    })
    .await
}

async fn update_dane(control: &Path, mode: DaneMode) -> anyhow::Result<()> {
    let ack = control.join("dane-applied");
    if ack.exists() {
        std::fs::remove_file(&ack)?;
    }
    std::fs::write(control.join("dane-mode.tmp"), mode.as_env())?;
    std::fs::rename(control.join("dane-mode.tmp"), control.join("dane-mode"))?;
    wait_file(&ack).await
}

async fn dane_policy_transition(
    initial: DaneMode,
    next: DaneMode,
    expected: kumo_log_types::RecordType,
) -> anyhow::Result<()> {
    let expect_delivery = expected == Delivery;
    let control = tempfile::tempdir()?;
    let (_ca, options) = trusted_sink(&["mail.shared.example.com"])?;
    let mut daemon = options
        .env("KUMOD_MTA_STS_DANE", initial.as_env())
        .env("KUMOD_MTA_STS_NO_STS", "1")
        .env("KUMOD_MTA_STS_TLS", "Disabled")
        .env("KUMOD_MTA_STS_NO_RETRY", "1")
        .env(
            "KUMOD_MTA_STS_CONTROL",
            control.path().display().to_string(),
        )
        .start()
        .await?;
    let mut client = daemon.smtp_client().await?;
    send(&mut client, "first@enforce.example.com").await?;
    anyhow::ensure!(
        daemon
            .wait_for_maildir_count(1, Duration::from_secs(10))
            .await
    );
    update_dane(control.path(), next).await?;
    send(&mut client, "second@enforce.example.com").await?;
    anyhow::ensure!(
        daemon
            .wait_for_source_summary(
                |s| s.get(&Delivery).copied().unwrap_or(0) > 1
                    || s.get(&TransientFailure).copied().unwrap_or(0) > 0,
                Duration::from_secs(10)
            )
            .await
    );
    std::fs::write(control.path().join("stop"), "")?;
    daemon.stop_both().await?;
    let records = daemon.source.collect_logs().await?;
    let second = records
        .iter()
        .find(|r| {
            matches!(r.kind, Delivery | TransientFailure)
                && r.recipient
                    .iter()
                    .any(|addr| addr == "second@enforce.example.com")
        })
        .context("second result")?;
    anyhow::ensure!(
        second.kind == expected,
        "{initial:?} → {next:?}: {second:?}"
    );
    if expect_delivery {
        anyhow::ensure!(second.tls_cipher.is_some());
    }
    anyhow::ensure!(
        daemon.extract_maildir_messages()?.len() == if expect_delivery { 2 } else { 1 }
    );
    Ok(())
}
#[tokio::test]
async fn mta_sts_disabled_dane_rechecks_changed_records() -> anyhow::Result<()> {
    dane_policy_transition(DaneMode::Matching, DaneMode::Mismatch, TransientFailure).await
}
#[tokio::test]
async fn mta_sts_disabled_dane_rechecks_temporary_failure() -> anyhow::Result<()> {
    dane_policy_transition(DaneMode::Matching, DaneMode::ServFail, TransientFailure).await
}
#[tokio::test]
async fn mta_sts_disabled_dane_upgrades_plaintext() -> anyhow::Result<()> {
    dane_policy_transition(DaneMode::Absent, DaneMode::Matching, Delivery).await
}
#[tokio::test]
async fn mta_sts_disabled_dane_unusable_requires_encryption() -> anyhow::Result<()> {
    dane_policy_transition(DaneMode::Absent, DaneMode::Unusable, Delivery).await
}

/// A TLSA failure excludes that host, not a backup MX with its own valid
/// no-TLSA result. No message data may go to the failed primary.
#[tokio::test]
async fn mta_sts_dane_failure_tries_authorized_backup() -> anyhow::Result<()> {
    let (_ca, options) = trusted_sink(&["mail.shared.example.com"])?;
    let mut daemon = options
        .env("KUMOD_MTA_STS_BACKUP", "1")
        .env("KUMOD_MTA_STS_DANE", DaneMode::ServFail.as_env())
        .env("KUMOD_MTA_STS_NO_STS", "1")
        .env("KUMOD_MTA_STS_TLS", "Disabled")
        .env("KUMOD_HIDE_STARTTLS", "1")
        .env("KUMOD_MTA_STS_NO_RETRY", "1")
        .start()
        .await?;
    let trace = daemon.source.trace_client().await?;
    let mut client = daemon.smtp_client().await?;
    send(&mut client, "recip@enforce.example.com").await?;
    anyhow::ensure!(
        daemon
            .wait_for_maildir_count(1, Duration::from_secs(10))
            .await
    );
    anyhow::ensure!(
        trace
            .wait_for(
                |events| events.iter().any(|event| {
                    matches!(&event.payload, TraceSmtpClientV1Payload::Diagnostic { message, .. }
            if message.contains("DANE TLSA lookup for mail.shared.example.com")
                && message.contains("could not be securely resolved"))
                }),
                Duration::from_secs(10)
            )
            .await,
        "primary TLSA failure was not observed"
    );
    trace.stop().await?;
    daemon.stop_both().await?;
    let records = daemon.source.collect_logs().await?;
    let delivery = records
        .iter()
        .find(|r| r.kind == Delivery)
        .context("backup delivery")?;
    anyhow::ensure!(
        delivery
            .peer_address
            .as_ref()
            .is_some_and(|a| a.name == "mail.backup.example.com.")
            && delivery.num_attempts == 0
            && delivery.tls_cipher.is_none(),
        "{delivery:?}"
    );
    anyhow::ensure!(daemon.extract_maildir_messages()?.len() == 1);
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AddressRefreshAt {
    Ehlo,
    Reuse,
}

async fn dane_address_refresh(at: AddressRefreshAt) -> anyhow::Result<()> {
    let control = tempfile::tempdir()?;
    let (_ca, mut options) = trusted_sink(&["mail.shared.example.com"])?;
    options = options
        .env("KUMOD_MTA_STS_DANE", DaneMode::Matching.as_env())
        .env("KUMOD_MTA_STS_NO_STS", "1")
        .env("KUMOD_MTA_STS_TLS", "Disabled")
        .env("KUMOD_MTA_STS_NO_RETRY", "1")
        .env(
            "KUMOD_MTA_STS_CONTROL",
            control.path().display().to_string(),
        );
    if at == AddressRefreshAt::Ehlo {
        options = options
            .env("KUMOD_MTA_STS_HOLD_EHLO", "1")
            .env("KUMOD_HIDE_STARTTLS", "1");
    }
    let mut daemon = options.start().await?;
    let mut client = daemon.smtp_client().await?;
    send(&mut client, "first@enforce.example.com").await?;
    if at == AddressRefreshAt::Ehlo {
        wait_file(&control.path().join("ehlo-entered")).await?;
    } else {
        anyhow::ensure!(
            daemon
                .wait_for_maildir_count(1, Duration::from_secs(10))
                .await
        );
    }
    update_dane(control.path(), DaneMode::AddressAbsent).await?;
    if at == AddressRefreshAt::Ehlo {
        std::fs::write(control.path().join("ehlo-release"), "")?;
    } else {
        send(&mut client, "second@enforce.example.com").await?;
    }
    let delivered_before_refresh = usize::from(at == AddressRefreshAt::Reuse);
    anyhow::ensure!(
        daemon
            .wait_for_source_summary(
                |s| s.get(&TransientFailure).copied().unwrap_or(0) > 0
                    || s.get(&Delivery).copied().unwrap_or(0) > delivered_before_refresh,
                Duration::from_secs(10)
            )
            .await
    );
    std::fs::write(control.path().join("stop"), "")?;
    daemon.stop_both().await?;
    let records = daemon.source.collect_logs().await?;
    anyhow::ensure!(
        records
            .iter()
            .any(|r| r.kind == TransientFailure && r.response.content.contains("no addresses")),
        "address refresh bypassed DANE: {records:?}"
    );
    anyhow::ensure!(daemon.extract_maildir_messages()?.len() == delivered_before_refresh);
    Ok(())
}

#[tokio::test]
async fn mta_sts_dane_address_refresh_before_handshake() -> anyhow::Result<()> {
    dane_address_refresh(AddressRefreshAt::Ehlo).await
}

#[tokio::test]
async fn mta_sts_dane_address_refresh_before_reuse() -> anyhow::Result<()> {
    dane_address_refresh(AddressRefreshAt::Reuse).await
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CollisionPlan {
    OtherCandidates,
    LastCandidate,
    FailedAuthorizedCandidate,
}

impl CollisionPlan {
    fn as_env(self) -> &'static str {
        match self {
            Self::OtherCandidates => "remaining",
            Self::LastCandidate => "exhausted",
            Self::FailedAuthorizedCandidate => "failure",
        }
    }
}

async fn site_collision_preserves_plan(plan: CollisionPlan) -> anyhow::Result<()> {
    let (_ca, options) = trusted_sink(&["b.x.targets.test", "c.y.targets.test"])?;
    let mut daemon = options
        .env("KUMOD_MTA_STS_COLLISION", plan.as_env())
        // Do not race the sink idle timeout while waiting for source log flush.
        .env("KUMOD_SINK_CLIENT_TIMEOUT", "30s")
        .env("KUMOD_MTA_STS_NO_RETRY", "1")
        .start()
        .await?;
    let mut client = daemon.smtp_client().await?;
    send(&mut client, "first@collision-a.example.com").await?;
    anyhow::ensure!(
        daemon
            .wait_for_maildir_count(1, Duration::from_secs(10))
            .await
    );
    send(&mut client, "second@collision-b.example.com").await?;
    anyhow::ensure!(
        daemon
            .wait_for_source_summary(
                |s| s.get(&Delivery).copied().unwrap_or(0) > 1
                    || s.get(&TransientFailure).copied().unwrap_or(0) > 0,
                Duration::from_secs(10)
            )
            .await
    );
    send(&mut client, "third@collision-a.example.com").await?;
    anyhow::ensure!(
        daemon
            .wait_for_maildir_count(2, Duration::from_secs(10))
            .await
    );
    daemon.stop_both().await?;
    let records = daemon.source.collect_logs().await?;
    let first = records
        .iter()
        .find(|r| r.kind == Delivery)
        .context("first delivery")?;
    let second = records
        .iter()
        .find(|r| {
            matches!(r.kind, Delivery | TransientFailure)
                && r.recipient
                    .iter()
                    .any(|addr| addr == "second@collision-b.example.com")
        })
        .context("second result")?;
    anyhow::ensure!(
        first.site == second.site,
        "fixture must collide: {first:?} {second:?}"
    );
    anyhow::ensure!(
        second.kind == TransientFailure,
        "used an unauthorized MX: {second:?}"
    );
    anyhow::ensure!(
        second.response.code == 451,
        "routing mismatch counted as connection failure: {second:?}"
    );
    let third = records
        .iter()
        .find(|r| {
            r.kind == Delivery
                && r.recipient
                    .iter()
                    .any(|addr| addr == "third@collision-a.example.com")
        })
        .context("third delivery")?;
    anyhow::ensure!(
        third.num_attempts == 0 && third.peer_address == first.peer_address,
        "healthy candidate was lost: {first:?} {third:?}"
    );
    if plan == CollisionPlan::FailedAuthorizedCandidate {
        anyhow::ensure!(
            second
                .response
                .content
                .contains("certificate verify failed"),
            "lost candidate failure: {second:?}"
        );
    } else {
        assert_same_sink_connection(&daemon).await?;
    }
    anyhow::ensure!(daemon.extract_maildir_messages()?.len() == 2);
    Ok(())
}

#[tokio::test]
async fn mta_sts_site_collision_does_not_authorize_other_hosts() -> anyhow::Result<()> {
    site_collision_preserves_plan(CollisionPlan::OtherCandidates).await
}

#[tokio::test]
async fn mta_sts_site_collision_preserves_last_candidate() -> anyhow::Result<()> {
    site_collision_preserves_plan(CollisionPlan::LastCandidate).await
}

#[tokio::test]
async fn mta_sts_site_collision_retains_candidate_failures() -> anyhow::Result<()> {
    site_collision_preserves_plan(CollisionPlan::FailedAuthorizedCandidate).await
}
