//! Diagnostics for the local outbound SMTP logs. These structures deliberately
//! have no catch-all map: a diagnostic cannot replace disposition fields or
//! introduce a command, envelope or message into a connection record.
use chrono::{DateTime, Utc};
use rfc5321::EnhancedStatusCode;
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::skip_serializing_none;
use std::net::IpAddr;
use uuid::Uuid;

/// A step, outcome or other short label supplied by the SMTP client; never a
/// command with arguments or an error message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct SmtpLogLabel(String);

impl SmtpLogLabel {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&'static str> for SmtpLogLabel {
    fn from(label: &'static str) -> Self {
        Self::try_from(label.to_owned()).unwrap_or_else(|_| Self("other".into()))
    }
}

impl TryFrom<String> for SmtpLogLabel {
    type Error = &'static str;

    fn try_from(label: String) -> Result<Self, Self::Error> {
        if label.is_empty()
            || label.len() > 48
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err("expected a short SMTP label");
        }
        Ok(Self(label))
    }
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpPeerResponse {
    #[serde(deserialize_with = "negative_code")]
    pub code: u16,
    pub enhanced_code: Option<EnhancedStatusCode>,
    pub reason: Option<SmtpLogLabel>,
    /// Parsed text from the SMTP peer, independent of classification or disposition rewrites.
    pub content: Option<String>,
    pub content_truncated: Option<bool>,
}

fn negative_code<'de, D: Deserializer<'de>>(d: D) -> Result<u16, D::Error> {
    let code = u16::deserialize(d)?;
    if (400..600).contains(&code) {
        Ok(code)
    } else {
        Err(serde::de::Error::custom(
            "expected a negative SMTP reply code",
        ))
    }
}

impl SmtpPeerResponse {
    pub fn new(code: u16, enhanced_code: Option<EnhancedStatusCode>) -> Self {
        Self {
            code,
            enhanced_code,
            reason: None,
            content: None,
            content_truncated: None,
        }
    }

    /// Attach the log prefix after the full observation has been matched and classified.
    pub fn with_content(mut self, mut text: String, already_truncated: bool) -> Self {
        let end = text.floor_char_boundary(256);
        self.content_truncated = (already_truncated || end < text.len()).then_some(true);
        text.truncate(end);
        self.content = (!text.is_empty()).then_some(text);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SmtpPeerReply {
    pub smtp_stage: SmtpLogLabel,
    pub response: SmtpPeerResponse,
}

/// Fields added to a message disposition. `response` on the disposition
/// remains the native result, which may have been synthesized or rewritten.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SmtpDispositionFields {
    pub connection_id: Option<Uuid>,
    pub transaction_number: Option<u64>,
    pub transaction_elapsed_ms: Option<f64>,
    pub connection_setup_ms: Option<f64>,
    pub smtp_stage: Option<SmtpLogLabel>,
    pub failure_kind: Option<SmtpLogLabel>,
    pub peer_response: Option<SmtpPeerResponse>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer_replies: Vec<SmtpPeerReply>,
    pub peer_replies_omitted: Option<u64>,
}

impl SmtpDispositionFields {
    pub fn clear_non_peer_response(&mut self) {
        // A locally generated negative disposition is not a peer reply.
        if self.smtp_stage.is_none()
            || self.failure_kind.as_ref().map(SmtpLogLabel::as_str) != Some("smtp_reply")
        {
            self.peer_response = None;
        }
    }
}

pub(crate) fn deserialize_disposition_fields<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<Box<SmtpDispositionFields>>, D::Error> {
    let fields = SmtpDispositionFields::deserialize(d)?;
    Ok((fields != SmtpDispositionFields::default()).then(|| Box::new(fields)))
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum SmtpConnectionEvent {
    Attempt {
        attempt_number: u64,
        mx: String,
        ip: Option<IpAddr>,
        preference: Option<u16>,
        outcome: SmtpLogLabel,
        elapsed_ms: f64,
        connection_id: Option<Uuid>,
        smtp_stage: Option<SmtpLogLabel>,
        failure_kind: Option<SmtpLogLabel>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        peer_replies: Vec<SmtpPeerReply>,
        peer_replies_omitted: Option<u64>,
    },
    AddressList {
        outcome: SmtpLogLabel,
        usable_ip_candidates: u64,
        address_list_build_ms: Option<f64>,
    },
}

// Names come from configuration or discovery, not the classification policy.
fn limit_name(name: &mut String) {
    if name.len() > 512 || name.chars().any(char::is_control) {
        *name = "unknown".into();
    }
}

/// A local file record for outbound SMTP setup. It has an event time but no
/// spool id, message creation time or envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConnectionRecord {
    #[serde(rename = "type")]
    kind: ConnectionRecordType,
    #[serde(flatten, with = "super::ts_serializer")]
    pub timestamp: DateTime<Utc>,
    pub session_id: Uuid,
    pub egress_source: String,
    #[serde(flatten)]
    pub event: SmtpConnectionEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ConnectionRecordType {
    SmtpConnection,
}

impl SmtpConnectionRecord {
    pub fn new(
        timestamp: DateTime<Utc>,
        session_id: Uuid,
        egress_source: &str,
        mut event: SmtpConnectionEvent,
    ) -> Self {
        let mut egress_source = egress_source.to_owned();
        limit_name(&mut egress_source);
        if let SmtpConnectionEvent::Attempt { mx, .. } = &mut event {
            limit_name(mx);
        }
        Self {
            kind: ConnectionRecordType::SmtpConnection,
            timestamp,
            session_id,
            egress_source,
            event,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    #[test]
    fn attempt_sanitizes_names_and_preserves_auth_reply() {
        let event = serde_json::from_value(json!({
            "event":"attempt", "attempt_number":1, "mx":"mx\nexample", "ip":"192.0.2.1",
            "outcome":"failed", "elapsed_ms":2.5, "smtp_stage":"auth", "failure_kind":"smtp_reply",
            "peer_replies":[{"smtp_stage":"auth", "response":{"code":535, "content":"Authentication credentials invalid"}}]
        }))
        .unwrap();
        let record =
            SmtpConnectionRecord::new(DateTime::UNIX_EPOCH, Uuid::nil(), &"x".repeat(513), event);
        assert_eq!(
            serde_json::to_value(record).unwrap(),
            json!({
                "type":"SmtpConnection", "timestamp":0, "event_time":"1970-01-01T00:00:00Z",
                "session_id":Uuid::nil(), "egress_source":"unknown", "event":"attempt",
                "attempt_number":1, "mx":"unknown", "ip":"192.0.2.1", "outcome":"failed", "elapsed_ms":2.5,
                "smtp_stage":"auth", "failure_kind":"smtp_reply",
                "peer_replies":[{"smtp_stage":"auth", "response":{"code":535, "content":"Authentication credentials invalid"}}]
            })
        );
    }

    #[test]
    fn transport_failure_keeps_only_independently_observed_peer_replies() {
        let mut fields: SmtpDispositionFields = serde_json::from_value(json!({
            "smtp_stage":"data_dot", "failure_kind":"response_timeout",
            "peer_response":{"code":421},
            "peer_replies":[{"smtp_stage":"rcpt_to", "response":{"code":450}}]
        }))
        .unwrap();
        fields.clear_non_peer_response();
        assert!(fields.peer_response.is_none());
        assert_eq!(fields.peer_replies[0].response.code, 450);
    }

    #[test]
    fn bounds_peer_text_at_utf8_boundaries_and_preserves_control_characters() {
        let prefix = "x".repeat(255);
        let exact = "é".repeat(128);
        for (input, already_truncated, expected, marker) in [
            (format!("{prefix}é"), false, prefix.as_str(), Some(true)),
            (exact.clone(), false, exact.as_str(), None),
            (exact.clone(), true, exact.as_str(), Some(true)),
            (
                "line\nwith\tcontrol\u{001b}".into(),
                false,
                "line\nwith\tcontrol\u{001b}",
                None,
            ),
        ] {
            let reply = SmtpPeerResponse::new(450, None).with_content(input, already_truncated);
            assert_eq!(reply.content.as_deref(), Some(expected));
            assert_eq!(reply.content_truncated, marker);
        }
    }
}
