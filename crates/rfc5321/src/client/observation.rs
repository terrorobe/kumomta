use super::{ClientError, Command, Instant, Response, SmtpClient, TlsOptions, TlsStatus};
use std::sync::Arc;
use std::time::Duration;

#[cfg(test)]
mod tests;

/// An operation on the SMTP connection, without command arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmtpStage {
    Banner,
    Ehlo,
    StartTls,
    Auth,
    Rset,
    MailFrom,
    RcptTo,
    Data,
    DataWrite,
    DataDot,
    Pipeline,
    Unilateral,
    Other,
}

impl SmtpStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Banner => "banner",
            Self::Ehlo => "ehlo",
            Self::StartTls => "starttls",
            Self::Auth => "auth",
            Self::Rset => "rset",
            Self::MailFrom => "mail_from",
            Self::RcptTo => "rcpt_to",
            Self::Data => "data",
            Self::DataWrite => "data_write",
            Self::DataDot => "data_dot",
            Self::Pipeline => "pipeline",
            Self::Unilateral => "unilateral",
            Self::Other => "other",
        }
    }
}

impl From<&Command> for SmtpStage {
    fn from(command: &Command) -> Self {
        match command {
            Command::Ehlo(_) | Command::Helo(_) | Command::Lhlo(_) => Self::Ehlo,
            Command::StartTls => Self::StartTls,
            Command::Auth { .. } => Self::Auth,
            Command::Rset => Self::Rset,
            Command::MailFrom { .. } => Self::MailFrom,
            Command::RcptTo { .. } => Self::RcptTo,
            Command::Data => Self::Data,
            Command::DataDot => Self::DataDot,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmtpFailureKind {
    SmtpReply,
    ResponseTimeout,
    WriteTimeout,
    Disconnect,
    ProtocolError,
    TlsError,
    LocalError,
}

impl SmtpFailureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SmtpReply => "smtp_reply",
            Self::ResponseTimeout => "response_timeout",
            Self::WriteTimeout => "write_timeout",
            Self::Disconnect => "disconnect",
            Self::ProtocolError => "protocol_error",
            Self::TlsError => "tls_error",
            Self::LocalError => "local_error",
        }
    }
}

/// Structured observations from one client. `PeerReply` contains the parsed
/// text sent by the peer; the client never attaches its own command arguments,
/// envelope or message data.
#[derive(Debug)]
pub enum SmtpObservation {
    /// One complete negative reply, before disposition selection or rewrites.
    /// The command is always absent. Text is limited to 1,024 UTF-8 bytes.
    /// A truncated prefix must not be used for classification.
    PeerReply {
        stage: SmtpStage,
        response: Response,
        truncated: bool,
    },
    /// A completed banner, greeting, TLS negotiation, or authentication step.
    Phase {
        stage: SmtpStage,
        duration: Duration,
        failure: Option<SmtpFailureKind>,
    },
    /// A MAIL FROM write is beginning (possibly as part of a pipeline).
    MailFromStarted,
    /// One send operation that reached MAIL FROM, not one event per recipient.
    TransactionFinished {
        duration: Duration,
        stage: SmtpStage,
        failure: Option<SmtpFailureKind>,
    },
    BeforeMailFromFailure {
        stage: SmtpStage,
        failure: SmtpFailureKind,
    },
}

/// Called inline, in wire order. Implementations must not block and should
/// bound any retained diagnostics separately from counting the observations.
pub trait SmtpClientObserver: std::fmt::Debug + Send + Sync {
    fn observe(&self, event: SmtpObservation);
}

impl SmtpObservation {
    pub(super) fn peer_reply(stage: SmtpStage, reply: &Response) -> Self {
        const MAX_PEER_TEXT: usize = 1024;
        let end = reply.content.floor_char_boundary(MAX_PEER_TEXT);
        Self::PeerReply {
            stage,
            response: Response {
                code: reply.code,
                enhanced_code: reply.enhanced_code,
                content: reply.content[..end].to_owned(),
                command: None,
            },
            truncated: end < reply.content.len(),
        }
    }
}

/// Keep the typed operation alongside its error until the send operation has
/// selected its terminal disposition. In particular, synthesized pipeline
/// results must not relabel a batch write as the first command's reply.
#[derive(Clone)]
pub(super) struct WireError {
    stage: SmtpStage,
    kind: SmtpFailureKind,
    pub error: ClientError,
}

impl WireError {
    pub fn new(stage: SmtpStage, error: ClientError) -> Self {
        use SmtpFailureKind::*;
        let kind = match &error {
            // Only the transport code that actually read a reply may assign
            // SmtpReply. A locally generated Rejected is still a local error.
            ClientError::Rejected(_) | ClientError::RejectedBatch(_) => LocalError,
            ClientError::TimeOutResponse { .. } => ResponseTimeout,
            ClientError::TimeOutData | ClientError::TimeOutRequest { .. } => WriteTimeout,
            ClientError::ReadError { .. }
            | ClientError::WriteError { .. }
            | ClientError::FlushError { .. }
            | ClientError::NotConnected => Disconnect,
            ClientError::Utf8(_)
            | ClientError::MalformedResponseLine(_)
            | ClientError::ResponseTooLong => ProtocolError,
            ClientError::FailedToBuildConnector { .. }
            | ClientError::NoUsableDaneTlsa { .. }
            | ClientError::SslErrorStack(_) => TlsError,
            ClientError::InvalidDnsName(_) => LocalError,
        };
        Self { stage, kind, error }
    }

    pub fn local_rejection(response: Response) -> Self {
        Self::new(SmtpStage::Other, ClientError::Rejected(response))
    }

    pub fn rejected(stage: SmtpStage, response: Response) -> Self {
        Self {
            stage,
            kind: Self::reply_failure([&response]),
            error: ClientError::Rejected(response),
        }
    }

    pub fn rejected_batch(responses: Vec<Response>) -> Self {
        Self {
            stage: SmtpStage::RcptTo,
            kind: Self::reply_failure(&responses),
            error: ClientError::RejectedBatch(responses),
        }
    }

    fn reply_failure<'a>(replies: impl IntoIterator<Item = &'a Response>) -> SmtpFailureKind {
        if replies.into_iter().any(|r| (400..600).contains(&r.code)) {
            SmtpFailureKind::SmtpReply
        } else {
            SmtpFailureKind::ProtocolError
        }
    }
}

pub(super) enum TransactionTimer {
    Disabled,
    AwaitingMail,
    Started {
        started: Instant,
        finished: Option<Instant>,
    },
}

impl TransactionTimer {
    pub fn start_mail(&mut self, client: &SmtpClient) {
        if let (Self::AwaitingMail, Some(observer), Some(_)) =
            (&*self, &client.observer, &client.socket)
        {
            *self = Self::Started {
                started: Instant::now(),
                finished: None,
            };
            observer.observe(SmtpObservation::MailFromStarted);
        }
    }

    pub fn mark_end(&mut self) {
        if let Self::Started { finished, .. } = self {
            *finished = Some(Instant::now());
        }
    }

    pub fn finish<T>(
        self,
        client: &SmtpClient,
        result: Result<T, WireError>,
    ) -> Result<T, ClientError> {
        if let Some(observer) = &client.observer {
            let error = result.as_ref().err();
            if let Self::Started { started, finished } = self {
                observer.observe(SmtpObservation::TransactionFinished {
                    duration: finished.unwrap_or_else(Instant::now) - started,
                    stage: error.map_or(SmtpStage::DataDot, |err| err.stage),
                    failure: error.map(|err| err.kind),
                });
            } else if let (Self::AwaitingMail, Some(err)) = (self, error) {
                observer.observe(SmtpObservation::BeforeMailFromFailure {
                    stage: err.stage,
                    failure: err.kind,
                });
            }
        }
        result.map_err(|err| err.error)
    }
}

impl SmtpClient {
    /// Enable or disable structured observations on this client. Independent
    /// of the raw SMTP tracer; neither is enabled by default.
    pub fn set_observer(&mut self, observer: Option<Arc<dyn SmtpClientObserver>>) {
        self.observer = observer;
    }

    fn timer(&self) -> Option<Instant> {
        self.observer.as_ref().map(|_| Instant::now())
    }

    pub(super) fn reply_timer(&self, expected: Option<u16>) -> Option<(Instant, u16)> {
        expected.and_then(|code| self.timer().map(|started| (started, code)))
    }

    fn observe_phase(&self, stage: SmtpStage, started: Instant, failure: Option<SmtpFailureKind>) {
        if let Some(observer) = &self.observer {
            observer.observe(SmtpObservation::Phase {
                stage,
                duration: started.elapsed(),
                failure,
            });
        }
    }

    pub(super) fn finish_reply_phase(
        &self,
        stage: SmtpStage,
        timer: Option<(Instant, u16)>,
        result: Result<Response, WireError>,
    ) -> Result<Response, ClientError> {
        if let Some((started, expected)) = timer {
            let failure = match &result {
                Err(err) => Some(err.kind),
                Ok(reply) if reply.code != expected => Some(WireError::reply_failure([reply])),
                Ok(_) => None,
            };
            self.observe_phase(stage, started, failure);
        }
        result.map_err(|err| err.error)
    }

    pub(super) async fn observe_tls(
        &mut self,
        options: TlsOptions,
        upgrade_command: Option<&Command>,
    ) -> Result<TlsStatus, ClientError> {
        let started = self.timer();
        let result = self.negotiate_tls(options, upgrade_command).await;
        if let Some(started) = started {
            let failure = match &result {
                Ok(TlsStatus::Info(_)) => None,
                Ok(TlsStatus::FailedHandshake(_)) => Some(SmtpFailureKind::TlsError),
                Err(err) => Some(err.kind),
            };
            self.observe_phase(SmtpStage::StartTls, started, failure);
        }
        result.map_err(|err| err.error)
    }

    pub(super) async fn read_response_at(
        &mut self,
        command: Option<&Command>,
        timeout_duration: Duration,
        flush_stage: SmtpStage,
    ) -> Result<Response, WireError> {
        let deadline = Instant::now() + timeout_duration;
        self.flush_request(command, timeout_duration, deadline)
            .await
            .map_err(|error| match error {
                // Preserve the public error while attributing a flush timeout to the write.
                ClientError::TimeOutResponse { .. } => WireError {
                    stage: flush_stage,
                    kind: SmtpFailureKind::WriteTimeout,
                    error,
                },
                _ => WireError::new(flush_stage, error),
            })?;
        let stage = command.map_or(flush_stage, SmtpStage::from);
        let response = self
            .read_reply(command, deadline)
            .await
            .map_err(|err| WireError::new(stage, err))?;
        if let Some(observer) = &self.observer {
            if (400..600).contains(&response.code) {
                observer.observe(SmtpObservation::peer_reply(stage, &response));
            }
        }
        Ok(response)
    }

    pub(super) async fn write_mail_data(
        &mut self,
        data: &[u8],
        timer: &mut TransactionTimer,
    ) -> Result<(), WireError> {
        self.write_data_with_timeout(data).await.map_err(|err| {
            timer.mark_end();
            WireError::new(SmtpStage::DataWrite, err)
        })
    }

    pub(super) async fn read_data_dot(
        &mut self,
        timer: &mut TransactionTimer,
    ) -> Result<Response, WireError> {
        let reply = self
            .read_response_at(
                Some(&Command::DataDot),
                self.timeouts.data_dot_timeout,
                SmtpStage::DataWrite,
            )
            .await;
        timer.mark_end();
        reply
    }
}
