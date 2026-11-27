---
tags:
 - logging
---

## Log Record

Message log records are JSON objects with the following shape. [SMTP connection records](#smtp-connection-records) describe connection setup and have no message envelope.

```json
{
    // The record type; can be one of "Reception", "Delivery",
    // "Bounce", "TransientFailure", "Expiration", "AdminBounce",
    // "OOB" or "Feedback"
    "type": "Delivery",

    // The message spool id; corresponds to the value returned by
    // message:id()
    "id": "1d98076abbbc11ed940250ebf67f93bd",

    // The envelope sender
    "sender": "user@sender.example.com",

    // The envelope recipient
    //
    // If the message has multiple recipients (eg: it was part of
    // an SMTP batch transaction) this will be an array of the
    // recipients. (Multi-recipient is possible {{since('2025.12.02-67ee9e96', inline=True)}})
    "recipient": "user@recipient.example.com",

    // Which named queue the message was associated with
    "queue": "campaign:tenant@domain",

    // Which MX site the message was being delivered to.
    // Empty string for Reception records.
    "site": "source2->(alt1|alt2|alt3|alt4)?.gmail-smtp-in.l.google.com.",

    // The size of the message payload, in bytes.
    // In situations where the message payload was unloaded from memory,
    // (most likely to see this with a subset of TransientFailure and
    // some Delayed logs), the size will be reported as zero because
    // we can't know the size without going to the expensive of loading
    // it back into memory.
    "size": 1047,

    // The response from the peer, if applicable
    "response": {
        // the SMTP status code
        "code": 250,

        // The ENHANCEDSTATUSCODE portion of the response parsed
        // out into individual fields.
        // This one is from a "2.0.0" status code
        "enhanced_code": {
            "class": 2,
            "subject": 0,
            "detail": 0,
        },

        // the remainder of the response content
        "content": "OK ids=8a5475ccbbc611eda12250ebf67f93bd",

        // the SMTP command verb to which the response was made.
        // eg: "MAIL FROM", "RCPT TO" etc. "." isn't really a command
        // but is used to represent the response to the final ".:
        // we send to indicate the end of the message payload.
        // This field can be nil/absent in some cases, particularly
        // for Rejection records for incoming SMTP in older
        // versions of kumomta.
        "command": "."
    },

    // Information about the peer in the communication. This is either
    // the submitter or the receiver, depending on the record type
    "peer_address": {
        // When delivering, this is the name from the MX record.
        // When receiving, this is the EHLO/HELO string sent by
        // the sender
        "name": "gmail-smtp-in.l.google.com.",
        "addr": "142.251.2.27"
    },

    // The time at which this record was generated, expressed
    // as a unix timestamp: seconds since the unix epoch
    "timestamp": 1757675281,

    // The time at which this record was generated, expressed
    // as an RFC 3339 string {{since('2025.10.06-5ec871ab', inline=True)}}
    "event_time": "2025-09-12T11:08:01.440526026Z",

    // The time at which the message was received, expressed
    // as a unix timestamp: seconds since the unix epoch
    "created": 1757675281,

    // The time at which the message was received, expressed
    // as an RFC 3339 string {{since('2025.10.06-5ec871ab', inline=True)}}
    "created_time": "2025-09-12T11:08:01.440526026Z",

    // The number of delivery attempts.
    "num_attempts": 0,

    // the classification assigned by the bounce classifier,
    // or Uncategorized if unknown or the classifier is not configured.
    "bounce_classification": "Uncategorized",

    // The name of the egress pool used as the source for the delivery
    "egress_pool": "pool0",

    // The name of the selected egress source (a member of the egress pool)
    // used for the delivery
    "egress_source": "source2",

    // For SMTP delivery, the source address (and port) that was used.
    // {{since('2024.09.02-c5476b89', inline=True)}}
    "source_address": {
        // The source address. The port number may be unknown and reported
        // as zero when using a proxy protocol.
        "address": "10.0.0.1:53210",
        // If a proxy protocol was used, this field will be
        // set to its name. It may be null/not set for no proxy,
        // "haproxy" or "socks5".
        "protocol": "socks5",
        // If a proxy protocol was used, this field will be
        // set to the proxy server address. It will be null/not set
        // when no proxy was used.
        "server": "192.168.1.1:5000"
    },

    // when "type" == "Feedback", holds the parsed feedback report
    "feedback_report": null,

    // holds the values of the list of meta fields from the logger
    // configuration
    "meta": {},

    // holds the values of the list of message headers from the logger
    // configuration
    "headers": {},

    // The protocol used to deliver, or attempt to deliver, this message.
    // May be null or unset for expirations or administrative bounces
    // or other similar situations.
    // "ESMTP" for SMTP, "Maildir" for maildir and "Lua" for a lua delivery
    // mechanism.
    "delivery_protocol": "ESMTP",

    // The protocol used to receive the message
    // "ESMTP" for SMTP, "HTTP" for the HTTP injection API, "LogRecord"
    // for messages captured via `configure_log_hook`.
    // This information is also stored in the message meta key named
    // "reception_protocol".
    "reception_protocol": "ESMTP",

    // The node uuid. This identifies the node independently from its
    // IP address or other characteristics present in this log record.
    "nodeid": "557f3ad4-2c8c-11ee-976e-782d7e12e173",

    // Information about TLS used for outgoing SMTP, if applicable.
    // Incoming TLS info is available {{since('2025.10.06-5ec871ab', inline=True)}}.
    "tls_cipher": "TLS_AES_256_GCM_SHA384",
    "tls_protocol_version": "TLSv1.3",
    "tls_peer_subject_name": ["C=US","ST=CA","L=SanFrancisco","O=Fort-Funston",
                              "OU=MyOrganizationalUnit","CN=do.havedane.net",
                              "name=EasyRSA","emailAddress=me@myhost.mydomain"]},

    // A correlating session identifier. Messages received via
    // the same connection will have the same session_id in their
    // Reception or Rejection records. Messages being sent via the
    // same session will have the same session_id in their TransientFailure,
    // Delivery and Bounce records.
    // May not be set in situations where there is no active session.
    // {{since('2025.01.23-7273d2bc', inline=True)}}
    "session_id": "9bcd689e-23d9-41b7-a015-63a1382f8b57"
}
```

## Record Types

The following record types are defined:

* `"Reception"` - logging the reception of a message via SMTP or via
  the HTTP injection API
* `"Delivery"` - logging the successful delivery of a message via SMTP
* `"Bounce"` - logging a permanent failure response and end of delivery
  attempts for the message.
* `"TransientFailure"` - logging a transient failure when attempting delivery
* `"Expiration"` - logged when the message exceeds the configured maximum
  lifetime in the queue.
* `"AdminBounce"` - logged when an administrator uses the `/api/admin/bounce`
  API to fail message(s).
* `"OOB"` - when receiving an out of band bounce with an attached RFC3464
  delivery status report, the parsed report is used to synthesize an OOB
  record for each recipient in the report.
* `"Feedback"` - when receiving an ARF feedback report, instead of logging
  a `"Reception"`, a `"Feedback"` record is logged instead with the report
  contents parsed out and made available in the `feedback_report` field.
* `"Rejection"` - logging a 4xx or 5xx response generated by KumoMTA
  in response to an incoming SMTP command. {{since('2024.06.10-84e84b89', inline=True)}}
* `"AdminRebind"` - a message was moved from one queue to another as part of a
  [rebind](kcli/rebind.md). {{since('2024.09.02-c5476b89', inline=True)}}
* `"DeferredInjectionRebind"` - a message was moved from a special internal
  deferred injection queue and into some other queue. {{since('2025.01.23-7273d2bc', inline=True)}}
* `"Delayed"` - explains why a message landed in the scheduled queue when
  it doesn't otherwise have a `TransientFailure` record logged. {{since('2025.01.23-7273d2bc', inline=True)}}
* `"XferOut"` - a message was transferred out from the current node to another
  kumomta node as part of an [xfer](kcli/xfer.md). {{since('2025.12.02-67ee9e96', inline=True)}}
* `"XferIn"` - a message was transferred in to the current node from another
  kumomta node as part of an [xfer](kcli/xfer.md). {{since('2025.12.02-67ee9e96', inline=True)}}
* `"SmtpConnection"` - a local record of an outbound SMTP connection attempt or address-list build. See [SMTP connection records](#smtp-connection-records). {{since('dev', inline=True)}}

## Outbound SMTP disposition fields

{{since('dev')}}

When [outbound SMTP client telemetry](kumo/configure_smtp_client_telemetry.md) is enabled, local `Delivery`, `TransientFailure` and `Bounce` records can include the following fields. Existing local templates can reference them directly or through `log_record`. They are not added to log hooks.

| Field | Meaning |
| --- | --- |
| `connection_id` | Identifies one SMTP-ready connection. Unlike `session_id`, it changes on reconnect. |
| `transaction_number` | Counts `MAIL FROM` attempts on that connection, starting at `1`. Recipients in one transaction share the same number. |
| `transaction_elapsed_ms` | Milliseconds from the start of `MAIL FROM` to the final reply or transport failure. |
| `connection_setup_ms` | On the first transaction only, milliseconds from the first TCP attempt to SMTP-ready, including failed attempts. Neither elapsed field is present if the transaction never started. |
| `smtp_stage`, `failure_kind` | Where and how SMTP failed. Stages name steps such as `rcpt_to`, `data`, `data_write`, `data_dot` or `pipeline`, without command arguments. `smtp_reply` identifies an actual negative peer reply; a local timeout is not a reply. |
| `peer_response` | The observed negative peer reply for `failure_kind: smtp_reply`, when available, even if policy rewrote the disposition. Contains `code` and, when available, `enhanced_code`, `reason` and the peer's parsed `content`. The peer's `enhanced_code` is preserved even when its class differs from `code`; it is absent when the peer supplied none. |
| `peer_replies`, `peer_replies_omitted` | Other negative replies from the transaction as `{smtp_stage, response}` pairs, with a count when replies were omitted. They are not additional failed recipients. |

At every stage, including AUTH, `content` comes from the server's reply, never from the client command or the [Lua classifier](events/smtp_client_classify_peer_reply.md). KumoMTA retains up to 256 bytes of the parsed text without splitting a UTF-8 character and sets `content_truncated: true` if it clipped the text. Treat peer text as untrusted: the server can echo addresses, credentials or message content. JSON escaping preserves the text; it does not sanitize or redact it.

The existing `response` describes the disposition and can contain native command and response text, including synthetic local errors. `event_time - created_time` is the age of the message, including retries, not a measurement of time in a particular queue.

## SMTP connection records

{{since('dev')}}

Each `SmtpConnection` record has `timestamp`, `event_time`, the dispatcher's `session_id`, and the selected `egress_source`. It has no spool ID, envelope, or message creation time. The `event` field determines the other top-level fields:

* `attempt` identifies an endpoint by `mx` and, when known, `ip` and MX `preference`. `attempt_number` starts at 1 for each new setup; `elapsed_ms` measures that attempt alone. The `outcome` is `smtp_ready` (with a `connection_id` that matches its dispositions) or `failed` (with `smtp_stage` and `failure_kind` when known). Observed negative replies use the same `peer_replies` format as [dispositions](#outbound-smtp-disposition-fields); `peer_replies_omitted` counts replies not retained.
* `address_list` reports `usable_ip_candidates` and `outcome`: `no_address` for an empty list, `partial` if a lookup yielded no usable addresses but another candidate is available, or `complete` otherwise. `address_list_build_ms` measures the interval from the first address lookup until the list is ready; it is absent when no lookup ran.

See [per_record](kumo/configure_local_logs/per_record.md#smtp-connection-records) for event selection and template configuration.

## Feedback Report

ARF feedback reports are parsed into a JSON object that has the following
structure.  The fields of the `feedback_report` correspond to those defined
by [RFC 5965](https://www.rfc-editor.org/rfc/rfc5965).

See also [trace_headers](kumo/start_esmtp_listener/trace_headers.md) for information
about the `supplemental_trace` field.

```json
{
    "type": "Feedback",
    "feedback_report": {
        "feedback_type": "abuse",
        "user_agent": "SomeGenerator/1.0",
        "version": 1,
        "arrival_date": "2005-03-08T18:00:00Z",
        "incidents": nil,
        "original_envelope_id": nil,
        "original_mail_from": "<somesender@example.net>",
        "reporting_mta": {
            "mta_type": "dns",
            "name": "mail.example.com",
        },
        "source_ip": "192.0.2.1",
        "authentication_results": [
            "mail.example.com; spf=fail smtp.mail=somesender@example.com",
        ],
        "original_rcpto_to": [
            "<user@example.com>",
        ],
        "reported_domain": [
            "example.net",
        ],
        "reported_uri": [
            "http://example.net/earn_money.html",
            "mailto:user@example.com",
        ],

        // any fields found in the report that do not correspond to
        // those defined by RFC 5965 are collected into this
        // extensions field
        "extensions": {
            "removal-recipient": [
                "user@example.com",
            ],
        },

        // The original message or message headers, if provided in
        // the report. This is emitted as a JSON string when the
        // bytes are valid UTF-8, and falls back to a JSON array of
        // byte values otherwise so that non-UTF-8 content is not
        // lossily transcoded. The same fallback applies to the
        // values in the `extensions` map above.
        "original_message": "From: <somesender@example.net>
Received: from mailserver.example.net (mailserver.example.net
    [192.0.2.1]) by example.com with ESMTP id M63d4137594e46;
    Tue, 08 Mar 2005 14:00:00 -0400
X-KumoRef: eyJfQF8iOiJcXF8vIiwicmVjaXBpZW50IjoidGVzdEBleGFtcGxlLmNvbSJ9
To: <Undisclosed Recipients>
Subject: Earn money
MIME-Version: 1.0
Content-type: text/plain
Message-ID: 8787KJKJ3K4J3K4J3K4J3.mail@example.net
Date: Thu, 02 Sep 2004 12:31:03 -0500

Spam Spam Spam
Spam Spam Spam
Spam Spam Spam
Spam Spam Spam
",

        // if original_message is present, and a kumo-style trace
        // header was decoded from it, then this holds the decoded
        // trace information
        "supplemental_trace": {
            "recipient": "test@example.com",
        },
    }
}
```

