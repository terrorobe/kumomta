//! Outbound observations are separate from delivery decisions. A plan may span
//! several sockets; only a socket that reached SMTP-ready has a connection ID.
use super::{Dispatcher, SmtpDispatcher};
use crate::logging::disposition::{log_smtp_disposition, LogDisposition};
use crate::logging::smtp_client::log_smtp_connection;
use crate::ready_queue::AttemptConnectionDisposition;
use crate::smtp_telemetry as metrics;
use dns_resolver::{has_colon_port, resolve_a_or_aaaa, IpLookupStrategy, Resolver};
use kumo_log_types::smtp::{
    SmtpConnectionEvent, SmtpDispositionFields, SmtpPeerReply, SmtpPeerResponse,
};
use kumo_log_types::ResolvedAddress;
use kumo_server_lifecycle::ShuttingDownError;
use mailexchanger::{AddressListStats, MailExchanger, ResolvedMxAddresses};
use parking_lot::Mutex;
use rfc5321::{Response, SmtpClientObserver, SmtpFailureKind, SmtpObservation, SmtpStage};
use std::io::ErrorKind;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UnixStream;
use uuid::Uuid;

// Limit retained diagnostics, not the number of recipients a refusal can affect.
const MAX_REPLIES: usize = 8;

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.
}

/// MX resolution may serve several plans, including from cache.
pub(crate) async fn resolve_smtp_mx(domain: &str) -> anyhow::Result<Arc<MailExchanger>> {
    let start = metrics::enabled().then(Instant::now);
    let resolved = MailExchanger::resolve(domain).await;
    if let Some(start) = start.filter(|_| !resolved.as_ref().is_ok_and(|mx| mx.is_domain_literal)) {
        metrics::phase("unknown", "mx_lookup", resolved.is_ok(), start.elapsed());
    }
    resolved
}

pub(super) struct AddressListLookup<'a> {
    pub(super) stats: Option<AddressListStats>,
    resolver: Option<&'a dyn Resolver>,
    strategy: IpLookupStrategy,
}

impl AddressListLookup<'_> {
    pub fn new(strategy: IpLookupStrategy) -> Self {
        Self {
            stats: metrics::enabled().then(AddressListStats::default),
            resolver: None,
            strategy,
        }
    }

    pub async fn resolve_host(&mut self, name: &str) -> anyhow::Result<Vec<ResolvedAddress>> {
        // resolve_a_or_aaaa handles literals and Unix sockets without a DNS lookup.
        let mut stats = self.stats.as_mut().filter(|_| {
            !name.starts_with('[') && name.parse::<kumo_address::host::HostAddress>().is_err()
        });
        if let Some(stats) = &mut stats {
            stats.start_lookup();
        }
        let resolved = resolve_a_or_aaaa(name, self.resolver, self.strategy).await?;
        if let Some(stats) = stats {
            stats.resolved_host(resolved.len());
        }
        Ok(resolved)
    }

    pub fn record(&self, dispatcher: &Dispatcher, addresses: &ResolvedMxAddresses) {
        let (Some(stats), ResolvedMxAddresses::Addresses(list)) = (&self.stats, addresses) else {
            return;
        };
        let elapsed = stats.first_lookup.map(|start| start.elapsed());
        let outcome = stats.outcome(list.len());
        if let Some(duration) = elapsed {
            metrics::address_list(outcome, duration);
        } else if !list.is_empty() {
            return; // No lookup and no empty list to diagnose.
        }
        log_smtp_connection(
            dispatcher.session_id,
            &dispatcher.egress_source.name,
            SmtpConnectionEvent::AddressList {
                outcome: outcome.into(),
                usable_ip_candidates: list.iter().filter(|a| a.addr.ip().is_some()).count() as u64,
                address_list_build_ms: elapsed.map(ms),
            },
            list.is_empty(),
            elapsed,
        );
    }

    pub fn into_plan(self, addresses: &[ResolvedAddress]) -> Option<Box<Plan>> {
        self.stats?;
        Some(Box::new(Plan {
            provider: metrics::plan_provider(addresses.iter().map(|addr| addr.name.as_str())),
            ..Plan::default()
        }))
    }
}

fn hostname(host: &str) -> &str {
    has_colon_port(host).map_or(host, |(name, _)| name)
}

#[derive(Debug, Default)]
pub(super) struct Plan {
    provider: &'static str,
    setup_start: Option<Instant>,
    tcp_candidates: usize,
    attempt_number: u64,
    socket: Option<Arc<SocketObserver>>,
}

impl SmtpDispatcher {
    pub(super) fn socket_observer(&self) -> Option<&SocketObserver> {
        self.telemetry.as_ref()?.socket.as_deref()
    }

    pub(super) fn take_socket_observer(&mut self) -> Option<Arc<SocketObserver>> {
        self.telemetry.as_mut()?.socket.take()
    }

    pub(super) fn observe_candidate(
        &mut self,
        dispatcher: &Dispatcher,
        address: &ResolvedAddress,
    ) -> Option<Arc<SocketObserver>> {
        let plan = self.telemetry.as_mut()?;
        let pref = dispatcher.mx.as_ref().filter(|mx| mx.is_mx).and_then(|mx| {
            let mut prefs = mx.by_pref.iter().filter_map(|(p, hosts)| {
                hosts
                    .iter()
                    .any(|h| hostname(h) == address.name)
                    .then_some(*p)
            });
            let pref = prefs.next()?;
            // ResolvedAddress alone cannot distinguish two MX RRs for the same host.
            prefs.next().is_none().then_some(pref)
        });
        let socket = Arc::new(SocketObserver {
            provider: metrics::provider(&address.name),
            mx: address.name.clone(),
            ip: address.addr.ip(),
            preference: pref,
            state: Mutex::default(),
        });
        plan.socket = Some(socket.clone());
        Some(socket)
    }

    // Called immediately after the candidate result, before the ready queue can
    // try its successor. Cancellation is not a completed candidate or plan.
    pub(super) async fn observe_attempt_result(
        &mut self,
        dispatcher: &Dispatcher,
        result: &anyhow::Result<AttemptConnectionDisposition>,
    ) {
        let Some(plan) = &mut self.telemetry else {
            return;
        };
        let ready = match result {
            Ok(AttemptConnectionDisposition::ConnectedNew) => true,
            Err(err) if !err.is::<ShuttingDownError>() => false,
            _ => return,
        };
        let end = Instant::now();
        let socket = if ready {
            plan.socket.clone()
        } else {
            plan.socket.take()
        };
        let attempt = socket.and_then(|s| {
            let start = s.state.lock().dial.take()?;
            if s.ip.is_some() {
                plan.setup_start.get_or_insert(start);
                if plan.tcp_candidates == 0 {
                    metrics::first_candidate(s.provider, ready);
                }
                plan.tcp_candidates += 1;
            }
            plan.attempt_number += 1;
            Some((s, end - start, plan.attempt_number))
        });

        let setup = plan.setup_start.map(|start| end - start);
        if ready || self.addresses.is_empty() {
            // A pre-dial failure can exhaust a plan that already tried an IP.
            if let Some(elapsed) = setup {
                metrics::setup(plan.provider, ready, plan.tcp_candidates, elapsed);
            }
            plan.setup_start = None;
            plan.tcp_candidates = 0;
            plan.attempt_number = 0;
        }
        let Some((socket, elapsed, attempt_number)) = attempt else {
            return;
        };
        let id = ready.then(|| socket.mark_ready(setup));
        let (event, notable) = socket.attempt_event(attempt_number, elapsed, id).await;
        log_smtp_connection(
            dispatcher.session_id,
            &dispatcher.egress_source.name,
            event,
            notable,
            Some(elapsed),
        );
        // Exclude time spent classifying and submitting diagnostics between candidates.
        if let Some(start) = &mut plan.setup_start {
            *start += end.elapsed();
        }
    }

    pub(super) async fn observe_delivery(
        &self,
        responses: &[Response],
        policy_veto: bool,
        whole_message_peer: Option<&ResolvedAddress>,
    ) -> Option<Box<Transaction>> {
        let socket = self.socket_observer()?;
        Some(Box::new(
            socket
                .delivery(responses, policy_veto, whole_message_peer)
                .await,
        ))
    }
}

pub(super) async fn connect_unix(
    path: &std::path::Path,
    observer: Option<&SocketObserver>,
) -> std::io::Result<UnixStream> {
    let timer = observer.map(|o| (o, Instant::now()));
    let stream = UnixStream::connect(path).await;
    if let Some((observer, start)) = timer {
        observer.dial(start, stream.as_ref().map(|_| ()).map_err(|e| e.kind()));
    }
    stream
}

struct PendingReply {
    provider: &'static str,
    stage: SmtpStage,
    response: Response,
    truncated: bool,
    // Setup/idle: one. During delivery: number of recipients assigned this reply.
    pending_count: u64,
}

impl PendingReply {
    async fn classify(&mut self) -> SmtpPeerResponse {
        let reason = metrics::peer_reply(
            self.provider,
            self.stage,
            &self.response,
            self.truncated,
            self.pending_count,
        )
        .await;
        self.pending_count = 0;
        let mut reply = SmtpPeerResponse::new(self.response.code, self.response.enhanced_code)
            .with_content(std::mem::take(&mut self.response.content), self.truncated);
        reply.reason = reason.map(Into::into);
        reply
    }
}

impl Drop for PendingReply {
    fn drop(&mut self) {
        // If classification was cancelled, preserve the assigned count as `other`.
        metrics::peer_reply_unclassified(self.provider, self.response.code, self.pending_count);
    }
}

#[derive(Default)]
struct Replies {
    items: Vec<PendingReply>,
    omitted: usize,
}

impl Replies {
    async fn classify(self) -> Vec<SmtpPeerReply> {
        let mut clean = Vec::with_capacity(self.items.len());
        for mut reply in self.items {
            clean.push(SmtpPeerReply {
                smtp_stage: reply.stage.as_str().into(),
                response: reply.classify().await,
            });
        }
        clean
    }
}

struct ReadySocket {
    id: Uuid,
    setup: Option<Duration>,
    attempted: u64,
    accepted: u64,
}

#[derive(Default)]
struct State {
    dial: Option<Instant>,
    setup_failure: Option<(&'static str, &'static str)>,
    ready: Option<ReadySocket>,
    in_transaction: bool,
    terminal: Option<(SmtpStage, Option<SmtpFailureKind>, Option<Duration>)>,
    replies: Replies,
}

pub(super) struct SocketObserver {
    provider: &'static str,
    mx: String,
    ip: Option<IpAddr>,
    preference: Option<u16>,
    state: Mutex<State>,
}

// Keep peer reply text in the configured file logs, not dispatcher debug output.
impl std::fmt::Debug for SocketObserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocketObserver")
            .field("mx", &self.mx)
            .field("ip", &self.ip)
            .finish_non_exhaustive()
    }
}

impl Drop for SocketObserver {
    fn drop(&mut self) {
        if let Some(ready) = self.state.get_mut().ready.take() {
            metrics::connection_closed(self.provider, ready.attempted, ready.accepted);
        }
    }
}

impl SocketObserver {
    fn mark_ready(&self, setup: Option<Duration>) -> Uuid {
        let id = Uuid::new_v4();
        self.state.lock().ready = Some(ReadySocket {
            id,
            setup,
            attempted: 0,
            accepted: 0,
        });
        id
    }

    async fn attempt_event(
        &self,
        attempt_number: u64,
        elapsed: Duration,
        connection_id: Option<Uuid>,
    ) -> (SmtpConnectionEvent, bool) {
        let (failure, replies) = {
            let mut state = self.state.lock();
            (
                state.setup_failure.take(),
                std::mem::take(&mut state.replies),
            )
        };
        let failed = connection_id.is_none();
        let failure = failed.then(|| failure.unwrap_or(("other", "local_error")));
        let notable = failed || !replies.items.is_empty();
        let event = SmtpConnectionEvent::Attempt {
            attempt_number,
            mx: self.mx.clone(),
            ip: self.ip,
            preference: self.preference,
            outcome: if failed { "failed" } else { "smtp_ready" }.into(),
            elapsed_ms: ms(elapsed),
            connection_id,
            smtp_stage: failure.map(|(stage, _)| stage.into()),
            failure_kind: failure.map(|(_, kind)| kind.into()),
            peer_replies_omitted: (replies.omitted != 0).then_some(replies.omitted as u64),
            peer_replies: replies.classify().await,
        };
        (event, notable)
    }

    pub fn dial(&self, start: Instant, result: Result<(), ErrorKind>) {
        self.state.lock().dial.get_or_insert(start);
        self.phase(
            if self.ip.is_some() {
                "tcp_connect"
            } else {
                "unix_connect"
            },
            start.elapsed(),
            result.err().map(|kind| match kind {
                ErrorKind::TimedOut => "connect_timeout",
                ErrorKind::ConnectionRefused => "connect_refused",
                _ => "connect_error",
            }),
        );
    }

    fn phase(&self, phase: &'static str, duration: Duration, failure: Option<&'static str>) {
        metrics::phase(self.provider, phase, failure.is_none(), duration);
        // A successful later operation supersedes a recovered failure. A local
        // policy error after it must not be attributed to that wire operation.
        self.state.lock().setup_failure = failure.map(|kind| (phase, kind));
    }

    pub async fn drain_idle(&self) {
        let replies = std::mem::take(&mut self.state.lock().replies);
        for mut reply in replies.items {
            reply.classify().await;
        }
    }

    async fn delivery(
        &self,
        responses: &[Response],
        policy_veto: bool,
        whole_message_peer: Option<&ResolvedAddress>,
    ) -> Transaction {
        let (terminal, ready, mut replies) = {
            let mut state = self.state.lock();
            (
                state.terminal.take(),
                state.ready.as_ref().map(|r| (r.id, r.setup, r.attempted)),
                std::mem::take(&mut state.replies),
            )
        };
        let mut fields = SmtpDispositionFields::default();
        let terminal = if policy_veto {
            Some((SmtpStage::Other, Some(SmtpFailureKind::LocalError), None))
        } else {
            terminal
        };
        if let Some((id, setup, number)) = ready {
            fields.connection_id = Some(id);
            if let Some((_, failure, Some(duration))) = terminal {
                let outcome = match failure {
                    None => "accepted",
                    Some(SmtpFailureKind::SmtpReply)
                        if responses.iter().any(|r| (400..500).contains(&r.code)) =>
                    {
                        "deferred"
                    }
                    Some(SmtpFailureKind::SmtpReply) => "bounced",
                    _ => "transport_error",
                };
                metrics::transaction_completed(self.provider, outcome, duration);
                fields.transaction_number = Some(number);
                fields.transaction_elapsed_ms = Some(ms(duration));
                fields.connection_setup_ms = setup.filter(|_| number == 1).map(ms);
            }
        }
        if let Some((stage, Some(kind), _)) = terminal {
            fields.smtp_stage = Some(stage.as_str().into());
            fields.failure_kind = Some(kind.as_str().into());
        }
        let primary_stage = match terminal {
            Some((stage, Some(SmtpFailureKind::SmtpReply), _)) => Some(stage),
            Some((_, None, Some(_))) => Some(SmtpStage::RcptTo),
            _ => None,
        };
        // Assign weights from the original recipient results, including failures before MAIL FROM (e.g. RSET).
        for reply in &mut replies.items {
            reply.pending_count = 0;
        }
        let mut next_slot = 0;
        let per_recipient = responses
            .iter()
            .map(|response| {
                let stage = primary_stage?;
                if !(400..600).contains(&response.code) {
                    return None;
                }
                // Before rewrite, negative RCPT results and their observations have the
                // same wire order. A global failure (including DATA dot) instead supplies
                // one primary for the whole batch; its RCPT refusals stay secondary.
                let slot =
                    (next_slot..replies.items.len()).find(|&i| replies.items[i].stage == stage);
                let primary = if let Some(i) = slot {
                    next_slot = i + usize::from(stage == SmtpStage::RcptTo);
                    replies.items[i].pending_count += 1;
                    Some(Primary::Retained(i))
                } else {
                    next_slot = replies.items.len();
                    (replies.omitted != 0).then(|| {
                        metrics::peer_reply_unclassified(self.provider, response.code, 1);
                        Primary::Omitted(response.code, response.enhanced_code)
                    })
                };
                Some((stage, primary))
            })
            .collect();
        fields.peer_replies_omitted = (replies.omitted != 0).then_some(replies.omitted as u64);
        fields.peer_replies = replies.classify().await;
        Transaction {
            whole_message_peer: whole_message_peer.cloned(),
            fields,
            per_recipient,
        }
    }
}

impl SmtpClientObserver for SocketObserver {
    fn observe(&self, event: SmtpObservation) {
        match event {
            SmtpObservation::PeerReply {
                stage,
                response,
                truncated,
            } => {
                let mut state = self.state.lock();
                let pending_count = u64::from(!state.in_transaction);
                if state.replies.items.len() == MAX_REPLIES {
                    state.replies.omitted += 1;
                    metrics::peer_reply_unclassified(self.provider, response.code, pending_count);
                } else {
                    state.replies.items.push(PendingReply {
                        provider: self.provider,
                        stage,
                        response,
                        truncated,
                        pending_count,
                    });
                }
            }
            SmtpObservation::Phase {
                stage,
                duration,
                failure,
            } => self.phase(stage.as_str(), duration, failure.map(|k| k.as_str())),
            SmtpObservation::MailFromStarted => {
                let mut state = self.state.lock();
                state.in_transaction = true;
                if let Some(r) = state.ready.as_mut() {
                    r.attempted += 1;
                    metrics::transaction_started(self.provider, r.attempted == 1);
                }
            }
            SmtpObservation::TransactionFinished {
                duration,
                stage,
                failure,
            } => {
                let mut state = self.state.lock();
                state.in_transaction = false;
                state.terminal = Some((stage, failure, Some(duration)));
                if failure.is_none() {
                    if let Some(r) = state.ready.as_mut() {
                        r.accepted += 1;
                    }
                }
            }
            SmtpObservation::BeforeMailFromFailure { stage, failure } => {
                self.state.lock().terminal = Some((stage, Some(failure), None))
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Primary {
    Retained(usize),
    Omitted(u16, Option<rfc5321::EnhancedStatusCode>),
}

pub(crate) struct Transaction {
    whole_message_peer: Option<ResolvedAddress>,
    fields: SmtpDispositionFields,
    per_recipient: Vec<Option<(SmtpStage, Option<Primary>)>>,
}

impl LogDisposition<'_> {
    pub(super) async fn log_smtp_recipient(self, txn: Option<&Transaction>, recipient: usize) {
        log_smtp_disposition(self, txn.map(|t| t.fields(recipient)), None).await;
    }

    // The ready queue's native error has no peer. Only local logs may use the saved address.
    pub(crate) async fn log_smtp_internal_error(self, txn: Option<&Transaction>) {
        let (fields, peer) = txn.and_then(Transaction::whole_message_error).unzip();
        log_smtp_disposition(self, fields, peer).await;
    }
}

impl Transaction {
    fn whole_message_error(&self) -> Option<(SmtpDispositionFields, &ResolvedAddress)> {
        let peer = self.whole_message_peer.as_ref()?;
        let fields = SmtpDispositionFields {
            smtp_stage: Some("other".into()),
            failure_kind: Some("local_error".into()),
            ..self.fields.clone()
        };
        Some((fields, peer))
    }

    fn fields(&self, recipient: usize) -> SmtpDispositionFields {
        let mut fields = self.fields.clone();
        let Some((stage, primary)) = self.per_recipient[recipient] else {
            return fields;
        };
        if fields.failure_kind.is_none() {
            fields.smtp_stage = Some(stage.as_str().into());
            fields.failure_kind = Some(SmtpFailureKind::SmtpReply.as_str().into());
        }
        match primary {
            Some(Primary::Retained(i)) => {
                fields.peer_response = Some(fields.peer_replies.remove(i).response)
            }
            Some(Primary::Omitted(code, dsn)) => {
                fields.peer_response = Some(SmtpPeerResponse::new(code, dsn));
                fields.peer_replies_omitted = fields
                    .peer_replies_omitted
                    .filter(|&n| n > 1)
                    .map(|n| n - 1);
            }
            None => {}
        }
        fields
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::{json, to_value};

    fn socket() -> SocketObserver {
        SocketObserver {
            provider: "other",
            mx: "mx.example".into(),
            ip: None,
            preference: None,
            state: Mutex::default(),
        }
    }

    fn reply(code: u16) -> Response {
        Response {
            code,
            enhanced_code: None,
            command: None,
            content: String::new(),
        }
    }

    fn negative(socket: &SocketObserver, stage: SmtpStage, code: u16) {
        socket.observe(SmtpObservation::PeerReply {
            stage,
            response: reply(code),
            truncated: false,
        });
    }

    fn finish(socket: &SocketObserver, stage: SmtpStage, failure: Option<SmtpFailureKind>) {
        socket.observe(SmtpObservation::TransactionFinished {
            duration: Duration::from_millis(3),
            stage,
            failure,
        });
    }

    #[tokio::test]
    async fn recovered_setup_replies_stay_on_the_ready_attempt() {
        let socket = socket();
        for _ in 0..=MAX_REPLIES {
            negative(&socket, SmtpStage::Ehlo, 450);
        }
        socket.phase("ehlo", Duration::ZERO, None);
        let id = socket.mark_ready(None);
        let (event, notable) = socket.attempt_event(2, Duration::ZERO, Some(id)).await;
        let record = to_value(event).unwrap();
        assert!(notable);
        assert_eq!(record["outcome"], "smtp_ready");
        assert_eq!(record["connection_id"], json!(id));
        assert!(record.get("failure_kind").is_none());
        assert_eq!(record["peer_replies"][0]["smtp_stage"], "ehlo");
        assert_eq!(record["peer_replies"][0]["response"]["code"], 450);
        assert_eq!(record["peer_replies_omitted"], 1);
        assert!(socket.state.lock().replies.items.is_empty());
    }

    #[tokio::test]
    async fn local_setup_error_does_not_blame_a_successful_command() {
        let socket = socket();
        socket.phase("ehlo", Duration::ZERO, None);
        let (event, notable) = socket.attempt_event(1, Duration::ZERO, None).await;
        let record = to_value(event).unwrap();
        assert!(notable);
        assert_eq!(record["smtp_stage"], "other");
        assert_eq!(record["failure_kind"], "local_error");
        assert!(record.get("peer_replies").is_none());
        assert!(record.get("connection_id").is_none());
    }

    #[tokio::test]
    async fn primary_refusal_and_setup_time_stay_on_first_transaction() {
        let socket = socket();
        let id = socket.mark_ready(Some(Duration::from_millis(7)));
        socket.observe(SmtpObservation::MailFromStarted);
        negative(&socket, SmtpStage::MailFrom, 450);
        negative(&socket, SmtpStage::Data, 503);
        finish(
            &socket,
            SmtpStage::MailFrom,
            Some(SmtpFailureKind::SmtpReply),
        );
        let peer = ResolvedAddress {
            name: "mx.example".into(),
            addr: "192.0.2.1".parse().unwrap(),
            is_secure: false,
        };
        let txn = socket.delivery(&[reply(450)], false, Some(&peer)).await;
        let (local, saved_peer) = txn.whole_message_error().unwrap();
        assert_eq!(saved_peer, &peer);
        assert_eq!(local.failure_kind.unwrap().as_str(), "local_error");
        let first = to_value(txn.fields(0)).unwrap();
        assert_eq!(first["connection_id"], json!(id));
        assert_eq!(first["connection_setup_ms"], 7.0);
        assert_eq!(first["transaction_elapsed_ms"], 3.0);
        assert_eq!(first["transaction_number"], 1);
        assert_eq!(first["smtp_stage"], "mail_from");
        assert_eq!(first["peer_response"]["code"], 450);
        assert_eq!(first["peer_replies"][0]["smtp_stage"], "data");
        assert_eq!(first["peer_replies"][0]["response"]["code"], 503);

        socket.observe(SmtpObservation::MailFromStarted);
        finish(&socket, SmtpStage::DataDot, None);
        let txn = socket.delivery(&[reply(250)], false, None).await;
        // A partial batch still has per-recipient diagnostics, but not for a whole-message error.
        assert!(txn.whole_message_error().is_none());
        let reused = to_value(txn.fields(0)).unwrap();
        assert_eq!(reused["connection_id"], json!(id));
        assert_eq!(reused["transaction_number"], 2);
        assert_eq!(reused["transaction_elapsed_ms"], 3.0);
        assert!(reused.get("connection_setup_ms").is_none());
        assert!(reused.get("peer_response").is_none());
        let state = socket.state.lock();
        let ready = state.ready.as_ref().unwrap();
        assert_eq!((ready.attempted, ready.accepted), (2, 1));
    }

    #[tokio::test]
    async fn pre_mail_veto_has_no_transaction_timing_or_peer_reply() {
        let socket = socket();
        socket.mark_ready(Some(Duration::from_millis(7)));
        let veto = to_value(socket.delivery(&[reply(451)], true, None).await.fields(0)).unwrap();
        assert_eq!(veto["failure_kind"], "local_error");
        assert!(veto.get("transaction_number").is_none());
        assert!(veto.get("transaction_elapsed_ms").is_none());
        assert!(veto.get("connection_setup_ms").is_none());
        assert!(veto.get("peer_response").is_none());
    }

    #[tokio::test]
    async fn mixed_recipients_keep_their_own_primary_reply_across_payload_limit() {
        let socket = socket();
        socket.mark_ready(None);
        socket.observe(SmtpObservation::MailFromStarted);
        let busy = Response::with_code_and_message(450, "4.3.1 busy");
        let mut responses = vec![busy.clone(); MAX_REPLIES + 2];
        responses[1] = reply(250);
        responses[2].content = "try later".into();
        for response in responses.iter().filter(|r| r.is_transient()) {
            socket.observe(SmtpObservation::PeerReply {
                stage: SmtpStage::RcptTo,
                response: response.clone(),
                truncated: false,
            });
        }
        finish(&socket, SmtpStage::DataDot, None);
        let txn = socket.delivery(&responses, false, None).await;
        let accepted = txn.fields(1);
        assert!(accepted.peer_response.is_none());
        assert!(accepted.failure_kind.is_none());
        assert_eq!(accepted.peer_replies.len(), MAX_REPLIES);
        assert_eq!(accepted.peer_replies_omitted, Some(1));

        // Removing the second "busy" must leave the first one ahead of "try later".
        let retained = txn.fields(3);
        assert_eq!(
            retained.peer_response.unwrap().content.as_deref(),
            Some("busy")
        );
        assert_eq!(retained.peer_replies[0], accepted.peer_replies[0]);
        let omitted = txn.fields(responses.len() - 1);
        assert_eq!(
            omitted.peer_response,
            Some(SmtpPeerResponse::new(450, busy.enhanced_code))
        );
        assert_eq!(omitted.peer_replies, accepted.peer_replies);
        assert!(omitted.peer_replies_omitted.is_none());
        assert_eq!(omitted.smtp_stage.unwrap().as_str(), "rcpt_to");
        assert_eq!(omitted.failure_kind.unwrap().as_str(), "smtp_reply");
        assert_eq!(omitted.transaction_number, accepted.transaction_number);
    }

    #[tokio::test]
    async fn mixed_recipients_share_a_global_final_dot_refusal() {
        let socket = socket();
        negative(&socket, SmtpStage::RcptTo, 450);
        negative(&socket, SmtpStage::DataDot, 550);
        finish(
            &socket,
            SmtpStage::DataDot,
            Some(SmtpFailureKind::SmtpReply),
        );
        // Native Rejected (not RejectedBatch) repeats the final dot for both recipients.
        let responses = [reply(550), reply(550)];
        let txn = socket.delivery(&responses, false, None).await;
        let fields = txn.fields(0);
        assert_eq!(fields, txn.fields(1));
        assert_eq!(fields.smtp_stage.unwrap().as_str(), "data_dot");
        assert_eq!(fields.peer_response.unwrap().code, 550);
        assert_eq!(fields.peer_replies.len(), 1);
        assert_eq!(fields.peer_replies[0].smtp_stage.as_str(), "rcpt_to");
        assert_eq!(fields.peer_replies[0].response.code, 450);
    }

    #[tokio::test]
    async fn address_list_stats_for_mixed_mx_list() {
        use crate::smtp_dispatcher::MxListEntry;
        use dns_resolver::{IpLookupStrategy, TestResolver};

        let resolver = TestResolver::default().with_bogus("broken.example.");
        let mut addresses = vec![];
        let mut lookup = AddressListLookup {
            resolver: Some(&resolver),
            strategy: IpLookupStrategy::Ipv4Only,
            stats: Some(AddressListStats::default()),
        };
        for entry in [
            MxListEntry::Name("[192.0.2.1]:2525".into()),
            MxListEntry::Name("/tmp/smtp.sock".into()),
            MxListEntry::Resolved(ResolvedAddress {
                name: "relay.example".into(),
                addr: "192.0.2.2".parse().unwrap(),
                is_secure: false,
            }),
        ] {
            entry
                .resolve_into(&mut addresses, &mut lookup, 10)
                .await
                .unwrap();
        }
        assert_eq!(addresses.len(), 3);
        let stats = lookup.stats.as_ref().unwrap();
        assert_eq!(stats.mx_hosts_looked_up, 0);
        assert!(stats.first_lookup.is_none());
        assert_eq!(stats.outcome(addresses.len()), "complete");

        // The failed DNS entry starts the timer; the local candidates still
        // make this a partial list, not a no-address result.
        MxListEntry::Name("broken.example.".into())
            .resolve_into(&mut addresses, &mut lookup, 10)
            .await
            .unwrap_err();
        assert_eq!(addresses.len(), 3);
        let stats = lookup.stats.as_ref().unwrap();
        assert_eq!(stats.mx_hosts_looked_up, 1);
        assert!(stats.first_lookup.is_some());
        assert_eq!(stats.outcome(addresses.len()), "partial");
    }
}
