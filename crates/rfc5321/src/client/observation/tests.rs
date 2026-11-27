use super::*;
use crate::{
    AsyncReadAndWrite, ClientError, ForwardPath, ReversePath, SmtpClient, SmtpClientTimeouts,
    TlsOptions,
};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{
    duplex, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
};

// An in-memory socket with bounded buffers. A peer that neither answers nor
// drains its side produces a real read or write timeout, without network I/O.
#[derive(Debug)]
struct Socket {
    wire: DuplexStream,
    flushes_before_stall: Option<usize>,
}
impl AsyncReadAndWrite for Socket {}
impl AsyncRead for Socket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.wire).poll_read(cx, buf)
    }
}
impl AsyncWrite for Socket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.wire).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(remaining) = &mut self.flushes_before_stall {
            if *remaining == 0 {
                return Poll::Pending;
            }
            *remaining -= 1;
        }
        Pin::new(&mut self.wire).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.wire).poll_shutdown(cx)
    }
}

#[derive(Default, Debug)]
struct Events(Mutex<Vec<SmtpObservation>>);
impl SmtpClientObserver for Events {
    fn observe(&self, event: SmtpObservation) {
        self.0.lock().unwrap().push(event);
    }
}
impl Events {
    fn take(&self) -> Vec<SmtpObservation> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }

    fn assert_transaction_only(
        &self,
        expected_stage: SmtpStage,
        expected_failure: Option<SmtpFailureKind>,
    ) {
        use SmtpObservation::*;
        let events = self.take();
        let [MailFromStarted, TransactionFinished { stage, failure, .. }] = events.as_slice()
        else {
            panic!("expected only transaction start and finish, got {events:?}");
        };
        assert_eq!((*stage, *failure), (expected_stage, expected_failure));
    }
}

fn fixture(buffer: usize) -> (SmtpClient, DuplexStream, Arc<Events>) {
    socket_fixture(buffer, None)
}

fn socket_fixture(
    buffer: usize,
    flushes_before_stall: Option<usize>,
) -> (SmtpClient, DuplexStream, Arc<Events>) {
    let (wire, peer) = duplex(buffer);
    let timeouts = SmtpClientTimeouts::short_timeouts();
    let socket = Socket {
        wire,
        flushes_before_stall,
    };
    let mut client = SmtpClient::with_stream(socket, "mx.example", timeouts);
    let events = Arc::new(Events::default());
    client.set_observer(Some(events.clone()));
    (client, peer, events)
}

async fn send(client: &mut SmtpClient, data: &[u8]) -> Result<Response, ClientError> {
    client
        .send_mail(
            ReversePath::try_from("sender@example.org").unwrap(),
            ForwardPath::try_from("recipient@example.org").unwrap(),
            data,
        )
        .await
}

async fn pipelined_fixture(buffer: usize) -> (SmtpClient, DuplexStream, Arc<Events>) {
    let (mut client, mut peer, events) = fixture(buffer);
    peer.write_all(b"250-mx.example\r\n250 PIPELINING\r\n")
        .await
        .unwrap();
    client.ehlo("sender.example.org").await.unwrap();
    client.set_enable_pipelining(true);
    assert!(matches!(
        events.take().as_slice(),
        [SmtpObservation::Phase {
            stage: SmtpStage::Ehlo,
            failure: None,
            ..
        }]
    ));
    (client, peer, events)
}

#[tokio::test]
async fn pipeline_reports_all_peer_refusals_once_before_selecting_terminal_reply() {
    use SmtpObservation::*;
    let (mut client, mut peer, events) = pipelined_fixture(4096).await;
    peer.write_all(b"550-5.7.1 first line\r\n550 5.7.1 second line\r\n450 4.7.1 busy\r\n503 5.5.1 bad sequence\r\n").await.unwrap();
    assert!(
        matches!(send(&mut client, b"body").await, Err(ClientError::Rejected(r)) if r.code == 550)
    );
    let observed = events.take();
    assert!(matches!(observed.as_slice(), [
        MailFromStarted,
        PeerReply { stage: SmtpStage::MailFrom, response: a, truncated: false },
        PeerReply { stage: SmtpStage::RcptTo, response: b, .. },
        PeerReply { stage: SmtpStage::Data, response: c, .. },
        TransactionFinished { stage: SmtpStage::MailFrom, failure: Some(SmtpFailureKind::SmtpReply), .. },
    ] if (a.code, b.code, c.code) == (550, 450, 503)
        && a.content == "first line\nsecond line" && a.command.is_none() && b.command.is_none() && c.command.is_none()));

    // Same physical connection: RSET, MAIL, RCPT, DATA, then the final dot.
    peer.write_all(b"250 reset\r\n250 sender\r\n250 recipient\r\n354 go\r\n250 accepted\r\n")
        .await
        .unwrap();
    assert_eq!(send(&mut client, b"body").await.unwrap().code, 250);
    events.assert_transaction_only(SmtpStage::DataDot, None);
}

#[tokio::test]
async fn mixed_recipient_pipeline_keeps_the_refusal_on_an_accepted_transaction() {
    let (mut client, mut peer, events) = pipelined_fixture(4096).await;

    peer.write_all(b"250 sender\r\n450 4.7.1 busy\r\n250 recipient\r\n354 go\r\n250 accepted\r\n")
        .await
        .unwrap();
    let result = client
        .send_mail_multi_recip(
            ReversePath::NullSender,
            vec![
                ForwardPath::try_from("first@example.org").unwrap(),
                ForwardPath::try_from("second@example.org").unwrap(),
            ],
            b"body",
        )
        .await
        .unwrap();
    assert_eq!(result.response.code, 250);
    assert_eq!(
        result
            .rcpt_responses
            .iter()
            .map(|r| r.code)
            .collect::<Vec<_>>(),
        [450, 250]
    );
    assert!(matches!(events.take().as_slice(), [
        SmtpObservation::MailFromStarted,
        SmtpObservation::PeerReply { stage: SmtpStage::RcptTo, response, .. },
        SmtpObservation::TransactionFinished { stage: SmtpStage::DataDot, failure: None, .. },
    ] if response.code == 450 && response.command.is_none()));
}

#[tokio::test]
async fn local_preflight_rejection_is_not_a_peer_reply_or_a_mail_attempt() {
    let (mut client, _peer, events) = fixture(4096);
    assert!(
        matches!(send(&mut client, &[0xff]).await, Err(ClientError::Rejected(r)) if r.code == 554)
    );
    assert!(matches!(
        events.take().as_slice(),
        [SmtpObservation::BeforeMailFromFailure {
            stage: SmtpStage::Other,
            failure: SmtpFailureKind::LocalError
        }]
    ));
}

async fn assert_final_dot_timeout(
    flushes_before_stall: Option<usize>,
    expected_stage: SmtpStage,
    expected_failure: SmtpFailureKind,
) {
    let (mut client, mut peer, events) = socket_fixture(4096, flushes_before_stall);
    client.timeouts.data_dot_timeout = Duration::ZERO;
    peer.write_all(b"250 sender\r\n250 recipient\r\n354 go\r\n")
        .await
        .unwrap();
    assert!(matches!(
        send(&mut client, b"body").await,
        Err(ClientError::TimeOutResponse {
            command: Some(Command::DataDot),
            ..
        })
    ));
    events.assert_transaction_only(expected_stage, Some(expected_failure));
}

#[tokio::test]
async fn final_dot_read_timeout_is_not_a_peer_refusal() {
    assert_final_dot_timeout(None, SmtpStage::DataDot, SmtpFailureKind::ResponseTimeout).await;
}

#[tokio::test]
async fn final_dot_flush_timeout_keeps_public_error_but_reports_a_data_write_failure() {
    // MAIL, RCPT and DATA flush; the flush after the final dot stalls.
    assert_final_dot_timeout(Some(3), SmtpStage::DataWrite, SmtpFailureKind::WriteTimeout).await;
}

#[tokio::test]
async fn pipeline_write_timeout_is_attributed_to_the_batch() {
    // Enough room for EHLO and its reply, but not the MAIL/RCPT/DATA batch.
    let (mut client, _peer, events) = pipelined_fixture(40).await;
    client.timeouts.mail_from_timeout = Duration::ZERO;
    client.timeouts.rcpt_to_timeout = Duration::ZERO;
    client.timeouts.data_timeout = Duration::ZERO;
    assert!(
        matches!(send(&mut client, b"body").await, Err(ClientError::TimeOutRequest { commands, .. }) if commands.len() == 3)
    );
    events.assert_transaction_only(SmtpStage::Pipeline, Some(SmtpFailureKind::WriteTimeout));
}

#[tokio::test]
async fn stalled_body_write_is_distinct_from_a_data_or_dot_reply() {
    let (mut client, mut peer, events) = fixture(128);
    client.timeouts.data_timeout = Duration::ZERO;
    peer.write_all(b"250 sender\r\n250 recipient\r\n354 go\r\n")
        .await
        .unwrap();
    assert!(matches!(
        send(&mut client, &[b'x'; 256]).await,
        Err(ClientError::TimeOutData)
    ));
    events.assert_transaction_only(SmtpStage::DataWrite, Some(SmtpFailureKind::WriteTimeout));
}

#[tokio::test]
async fn disconnect_at_sequential_rset_does_not_start_a_transaction() {
    let (mut client, mut peer, events) = fixture(4096);
    client.use_rset = true;
    let (result, ()) = tokio::join!(send(&mut client, b"body"), async {
        let mut line = [0; 6];
        peer.read_exact(&mut line).await.unwrap();
        assert_eq!(&line, b"RSET\r\n");
        assert!(events.take().is_empty());
        drop(peer);
    });
    assert!(matches!(
        result,
        Err(ClientError::ReadError {
            command: Some(Command::Rset),
            ..
        })
    ));
    assert!(matches!(
        events.take().as_slice(),
        [SmtpObservation::BeforeMailFromFailure {
            stage: SmtpStage::Rset,
            failure: SmtpFailureKind::Disconnect
        }]
    ));
}

#[tokio::test]
async fn auth_observation_keeps_the_reply_but_not_the_command() {
    let (mut client, mut peer, events) = fixture(4096);
    peer.write_all(b"535 5.7.8 Authentication credentials invalid\r\n")
        .await
        .unwrap();
    assert!(client
        .auth_plain("username", Some("password"))
        .await
        .is_err());
    assert!(matches!(events.take().as_slice(), [
        SmtpObservation::PeerReply {stage: SmtpStage::Auth, response, ..},
        SmtpObservation::Phase {stage: SmtpStage::Auth, failure: Some(SmtpFailureKind::SmtpReply), ..},
    ] if response.code == 535 && response.content == "Authentication credentials invalid" && response.command.is_none()));
}

#[tokio::test]
async fn banner_refusal_reports_a_bounded_utf8_prefix_and_phase_failure() {
    let (mut client, mut peer, events) = fixture(4096);
    let text = format!("{}é", "x".repeat(1023));
    peer.write_all(format!("421 4.3.2 {text}\r\n").as_bytes())
        .await
        .unwrap();
    assert_eq!(
        client
            .read_response(None, Duration::from_secs(1))
            .await
            .unwrap()
            .content,
        text
    );
    assert!(matches!(events.take().as_slice(), [
        SmtpObservation::PeerReply {stage: SmtpStage::Banner, response, truncated: true},
        SmtpObservation::Phase {stage: SmtpStage::Banner, failure: Some(SmtpFailureKind::SmtpReply), ..},
    ] if response.content == text[..1023] && response.code == 421));
}

#[tokio::test]
async fn starttls_refusal_reports_one_failed_negotiation() {
    let (mut client, mut peer, events) = fixture(4096);
    peer.write_all(b"454 TLS not available\r\n").await.unwrap();
    assert!(
        matches!(client.starttls(TlsOptions::default()).await, Err(ClientError::Rejected(r)) if r.code == 454)
    );
    assert!(matches!(
        events.take().as_slice(),
        [
            SmtpObservation::PeerReply {
                stage: SmtpStage::StartTls,
                ..
            },
            SmtpObservation::Phase {
                stage: SmtpStage::StartTls,
                failure: Some(SmtpFailureKind::SmtpReply),
                ..
            },
        ]
    ));
}

#[tokio::test]
async fn probing_an_idle_connection_is_not_a_banner_wait() {
    let (mut client, mut peer, events) = fixture(4096);
    assert!(client.check_unilateral_response().await.unwrap().is_none());
    assert!(events.take().is_empty());
    peer.write_all(b"421 closing\r\n").await.unwrap();
    assert_eq!(
        client
            .check_unilateral_response()
            .await
            .unwrap()
            .unwrap()
            .code,
        421
    );
    assert!(matches!(
        events.take().as_slice(),
        [SmtpObservation::PeerReply {
            stage: SmtpStage::Unilateral,
            ..
        }]
    ));
}
