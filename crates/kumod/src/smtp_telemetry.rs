//! Optional outbound SMTP telemetry. Only configured or protocol-defined values may
//! be passed to a metric vector. In particular, a caller's provider argument is not
//! necessarily a label: validate it again at the point of observation.
use anyhow::ensure;
use config::{any_err, declare_event, get_or_create_module, SerdeWrappedValue};
use kumo_prometheus::declare_metric;
use mlua::{Lua, Value};
use rfc5321::{EnhancedStatusCode, Response, SmtpStage};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use std::time::Duration;

#[cfg(test)]
mod tests;

const MAX_PROVIDERS: usize = 32;
const MAX_HOST_RULES: usize = 128;
const MAX_REASONS: usize = 16;
const MAX_CLASSIFIER_INPUT: usize = 1024;
// Include sub-second DNS/cache and LAN timings as well as SMTP command timeouts.
const SECONDS: &[f64] = &[
    0.001, 0.01, 0.05, 0.1, 0.25, 1., 2., 5., 15., 60., 300., 600.,
];
const ATTEMPTS: &[f64] = &[1., 2., 3., 4., 8., 16., 32., 64.];
// A strictly positive first boundary counts zero-use connections even in
// distribution exporters that discard zero-width buckets.
const TRANSACTIONS: &[f64] = &[0.5, 1., 2., 4., 8., 16., 32., 64., 256., 1024.];
const GROUP_OUTCOME: &[&str] = &["destination_relay_group", "outcome"];

// These are classic histograms: bucket limits are fixed, count-valued samples
// are not labels, and counts (including zero) and elapsed seconds are not clipped.
declare_metric! {
/// Seconds from the first TCP attempt until the plan is ready or exhausted.
static SETUP: HistogramVec("smtp_client_setup_duration_seconds", GROUP_OUTCOME, SECONDS.to_vec());
}
declare_metric! {
/// Plans whose first attempted IP reached a known setup outcome.
static FIRST: IntCounterVec("smtp_client_setup_first_candidate_total", GROUP_OUTCOME);
}
declare_metric! {
/// IPs tried per completed SMTP connection plan.
static PLAN_ATTEMPTS: HistogramVec("smtp_client_plan_attempts", GROUP_OUTCOME, ATTEMPTS.to_vec());
}
declare_metric! {
/// Seconds spent in one DNS or SMTP connection setup step.
static PHASE: HistogramVec("smtp_client_setup_phase_duration_seconds", &["destination_relay_group", "phase", "outcome"], SECONDS.to_vec());
}
declare_metric! {
/// Seconds from the first address lookup until the candidate list is available.
static ADDRESS_LIST: HistogramVec("smtp_client_setup_address_list_build_duration_seconds", &["outcome"], SECONDS.to_vec());
}
declare_metric! {
/// Seconds from MAIL FROM to the terminal SMTP reply or transport failure.
static TRANSACTION: HistogramVec("smtp_client_transaction_duration_seconds", GROUP_OUTCOME, SECONDS.to_vec());
}
declare_metric! {
/// SMTP transactions started, distinguishing first use and reuse of a connection.
static STARTED: IntCounterVec("smtp_client_transactions_total", &["destination_relay_group", "connection_use"]);
}
declare_metric! {
/// Attempted and accepted transactions per closed SMTP-ready connection, including unused connections.
static PER_CONNECTION: HistogramVec("smtp_client_transactions_per_connection", &["destination_relay_group", "measure"], TRANSACTIONS.to_vec());
}
declare_metric! {
/// Negative peer replies selected per recipient during delivery; setup and idle refusals count once per reply.
///
/// `smtp_code` is the peer's numeric reply code (400–599). For provider and reason
/// labels, see [kumo.configure_smtp_client_telemetry](../../kumo/configure_smtp_client_telemetry.md).
static REFUSALS: IntCounterVec("smtp_client_peer_refusals_total", &["destination_relay_group", "smtp_code", "reason"]);
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Params {
    providers: BTreeMap<String, Vec<String>>,
    reasons: Vec<String>,
}

#[derive(Default, PartialEq)]
struct Policy {
    providers: BTreeSet<String>,
    exact_hosts: BTreeMap<String, String>,
    subdomains: BTreeMap<String, String>,
    reasons: BTreeSet<String>,
}

// The allowlists are immutable for the process lifetime. Replacing them would
// leave old non-pruning Prometheus label sets behind after each reload.
static POLICY: OnceLock<Policy> = OnceLock::new();

fn valid_label(s: &str) -> bool {
    s.len() <= 48
        && s.starts_with(|c: char| c.is_ascii_lowercase())
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

fn valid_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
        && s.parse::<std::net::IpAddr>().is_err()
}

impl TryFrom<Params> for Policy {
    type Error = anyhow::Error;

    fn try_from(params: Params) -> anyhow::Result<Self> {
        ensure!(
            params.providers.len() <= MAX_PROVIDERS,
            "too many SMTP telemetry provider groups"
        );
        ensure!(
            params.providers.values().map(Vec::len).sum::<usize>() <= MAX_HOST_RULES,
            "too many SMTP telemetry hostname rules"
        );
        ensure!(
            params.reasons.len() <= MAX_REASONS && params.reasons.iter().all(|s| valid_label(s)),
            "invalid SMTP telemetry reason allowlist"
        );
        let mut policy = Self {
            reasons: params.reasons.into_iter().collect(),
            ..Self::default()
        };
        for (group, rules) in params.providers {
            ensure!(
                valid_label(&group) && !matches!(group.as_str(), "other" | "unknown"),
                "invalid SMTP telemetry provider group"
            );
            policy.providers.insert(group.clone());
            for rule in rules {
                let exact_only = rule.starts_with('=');
                let descendants_only = rule.starts_with("*.");
                let host = rule
                    .strip_prefix('=')
                    .or_else(|| rule.strip_prefix("*."))
                    .unwrap_or(&rule);
                let host = host.strip_suffix('.').unwrap_or(host);
                ensure!(valid_hostname(host), "invalid SMTP telemetry hostname rule");
                let host = host.to_ascii_lowercase();
                // A bare suffix matches both the apex and its descendants. Reject
                // ambiguous registrations rather than relying on Lua table order.
                let insert = |map: &mut BTreeMap<String, String>| -> anyhow::Result<()> {
                    let prior = map.entry(host.clone()).or_insert_with(|| group.clone());
                    ensure!(prior == &group, "conflicting SMTP telemetry hostname rules");
                    Ok(())
                };
                if !descendants_only {
                    insert(&mut policy.exact_hosts)?;
                }
                if !exact_only {
                    insert(&mut policy.subdomains)?;
                }
            }
        }
        Ok(policy)
    }
}

pub fn register(lua: &Lua) -> anyhow::Result<()> {
    let module = get_or_create_module(lua, "kumo")?;
    module.set(
        "configure_smtp_client_telemetry",
        lua.create_function(|_, params: SerdeWrappedValue<Params>| {
            let policy = Policy::try_from(params.0).map_err(any_err)?;
            if let Err(new) = POLICY.set(policy) {
                if POLICY.get() != Some(&new) {
                    return Err(mlua::Error::external(
                        "restart kumod to change the SMTP client telemetry allowlists",
                    ));
                }
            }
            Ok(())
        })?,
    )?;
    Ok(())
}

impl Policy {
    fn provider(&self, host: &str) -> &str {
        if host.is_empty() || host == "." {
            return "unknown";
        }
        // Explicit next hops can carry a port. Never parse a ready queue name.
        let host = dns_resolver::has_colon_port(host).map_or(host, |(name, _)| name);
        let host = host.strip_suffix('.').unwrap_or(host);
        if !valid_hostname(host) {
            return "other";
        }
        let host = host.to_ascii_lowercase();
        if let Some(group) = self.exact_hosts.get(&host) {
            return group;
        }
        let mut rest = host.as_str();
        while let Some((_, suffix)) = rest.split_once('.') {
            if let Some(group) = self.subdomains.get(suffix) {
                return group;
            }
            rest = suffix;
        }
        "other"
    }

    fn plan_provider<'a>(&self, mut hosts: impl Iterator<Item = &'a str>) -> &str {
        let Some(first) = hosts.next() else {
            return "unknown";
        };
        let group = self.provider(first);
        if hosts.all(|host| self.provider(host) == group) {
            group
        } else {
            "other"
        }
    }

    fn bounded_group(&self, group: &str) -> &str {
        if group == "unknown" {
            "unknown"
        } else {
            self.providers.get(group).map_or("other", String::as_str)
        }
    }
}

pub fn enabled() -> bool {
    POLICY.get().is_some()
}

pub fn provider(host: &str) -> &'static str {
    POLICY.get().map_or("unknown", |p| p.provider(host))
}

pub fn plan_provider<'a>(hosts: impl Iterator<Item = &'a str>) -> &'static str {
    POLICY.get().map_or("unknown", |p| p.plan_provider(hosts))
}

fn bounded_group(provider: &str) -> Option<&'static str> {
    Some(POLICY.get()?.bounded_group(provider))
}

pub fn phase(provider: &str, step: &'static str, ok: bool, duration: Duration) {
    let Some(group) = bounded_group(provider) else {
        return;
    };
    let group = match step {
        "mx_lookup" => "unknown", // The MX query is for the recipient domain.
        "tcp_connect" | "banner" | "ehlo" | "starttls" | "auth" => group,
        _ => return,
    };
    PHASE
        .with_label_values(&[group, step, if ok { "ok" } else { "error" }])
        .observe(duration.as_secs_f64());
}

pub fn address_list(outcome: &'static str, duration: Duration) {
    if enabled() && matches!(outcome, "complete" | "partial" | "no_address") {
        ADDRESS_LIST
            .with_label_values(&[outcome])
            .observe(duration.as_secs_f64());
    }
}

pub fn first_candidate(provider: &str, ready: bool) {
    if let Some(group) = bounded_group(provider) {
        FIRST
            .with_label_values(&[group, if ready { "ready" } else { "failed" }])
            .inc();
    }
}

pub fn setup(provider: &str, ready: bool, attempts: usize, duration: Duration) {
    let Some(group) = bounded_group(provider) else {
        return;
    };
    if attempts != 0 {
        let labels = &[group, if ready { "ready" } else { "exhausted" }];
        SETUP
            .with_label_values(labels)
            .observe(duration.as_secs_f64());
        PLAN_ATTEMPTS
            .with_label_values(labels)
            .observe(attempts as f64);
    }
}

pub fn transaction_started(provider: &str, first: bool) {
    if let Some(group) = bounded_group(provider) {
        STARTED
            .with_label_values(&[group, if first { "first" } else { "reused" }])
            .inc();
    }
}

pub fn transaction_completed(provider: &str, outcome: &'static str, duration: Duration) {
    if let Some(group) = bounded_group(provider) {
        if matches!(
            outcome,
            "accepted" | "deferred" | "bounced" | "transport_error"
        ) {
            TRANSACTION
                .with_label_values(&[group, outcome])
                .observe(duration.as_secs_f64());
        }
    }
}

pub fn connection_closed(provider: &str, attempted: u64, accepted: u64) {
    if let Some(group) = bounded_group(provider) {
        for (measure, count) in [("attempted", attempted), ("accepted", accepted)] {
            PER_CONNECTION
                .with_label_values(&[group, measure])
                .observe(count as f64);
        }
    }
}

#[derive(Clone, Serialize)]
struct ClassifierInput {
    code: u16,
    enhanced_code: Option<EnhancedStatusCode>,
    content: Option<String>,
}

#[derive(Default)]
struct Classification {
    reason: Option<String>,
}

impl mlua::FromLua for Classification {
    fn from_lua(value: Value, _: &Lua) -> mlua::Result<Self> {
        let Value::Table(table) = value else {
            return Err(mlua::Error::external("expected SMTP classification table"));
        };
        let reason = match table.raw_get::<Value>("reason")? {
            Value::String(s) if s.as_bytes().len() <= 48 => Some(s.to_str()?.to_string()),
            Value::Nil | Value::String(_) => None,
            _ => return Err(mlua::Error::external("expected SMTP classification string")),
        };
        Ok(Self { reason })
    }
}

declare_event! {
static CLASSIFY_REPLY: Single(
    "smtp_client_classify_peer_reply", provider: &str, stage: &str,
    response: SerdeWrappedValue<ClassifierInput>
) -> Option<Classification>;
}

impl Policy {
    fn count_refusal(&self, provider: &str, code: u16, reason: Option<&str>, count: u64) -> &str {
        let reason = reason
            .and_then(|s| self.reasons.get(s))
            .map_or("other", String::as_str);
        if count != 0 {
            REFUSALS
                .with_label_values(&[self.bounded_group(provider), &code.to_string(), reason])
                .inc_by(count);
        }
        reason
    }
}

/// Record a selected refusal when the observer cannot retain or finish classifying it.
pub fn peer_reply_unclassified(provider: &str, code: u16, count: u64) {
    if count == 0 {
        return;
    }
    if let Some(policy) = POLICY.get() {
        if (400..600).contains(&code) {
            policy.count_refusal(provider, code, None, count);
        }
    }
}

fn classifier_input(stage: SmtpStage, response: &Response, truncated: bool) -> ClassifierInput {
    use SmtpStage::*;
    let allow_text = matches!(
        stage,
        Banner | Ehlo | StartTls | Rset | MailFrom | RcptTo | Data | DataDot | Unilateral
    );
    // Only classify complete text. The local log may still retain a marked prefix.
    let content =
        (allow_text && !truncated && (1..=MAX_CLASSIFIER_INPUT).contains(&response.content.len()))
            .then(|| response.content.clone());
    ClassifierInput {
        code: response.code,
        enhanced_code: response.enhanced_code,
        content,
    }
}

async fn classify(group: &str, stage: SmtpStage, input: ClassifierInput) -> Classification {
    let run = async {
        let mut lua = config::load_config().await.ok()?;
        let result = lua
            .async_call_callback(
                &CLASSIFY_REPLY,
                (group, stage.as_str(), SerdeWrappedValue(input)),
            )
            .await;
        if result.is_ok() {
            lua.put();
        }
        // Lua errors can contain the peer's original text. Never propagate or log them.
        result.ok().flatten()
    };
    tokio::time::timeout(Duration::from_millis(100), run)
        .await
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// Return the bounded reason even for secondary replies, which are logged but not counted.
pub async fn peer_reply(
    provider: &str,
    stage: SmtpStage,
    response: &Response,
    truncated: bool,
    count: u64,
) -> Option<&'static str> {
    let policy = POLICY.get()?;
    if !(400..600).contains(&response.code) {
        return None;
    }
    let input = classifier_input(stage, response, truncated);
    let classified = classify(policy.bounded_group(provider), stage, input).await;
    // There is no await between counting and returning. The dispatcher's pending
    // reply guard owns the unclassified increment if this future is cancelled.
    Some(policy.count_refusal(provider, response.code, classified.reason.as_deref(), count))
}
