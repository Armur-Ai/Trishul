# VIBE-WEBHOOK-001: Unverified provider webhook handler

A webhook handler reads the raw body but never verifies the signature.

## Metadata

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Confidence | 0.50 |
| Maturity | stable |
| Mode | comment |
| Languages | javascript, typescript, python |
| File kinds | source |
| CWE | CWE-345 |
| OWASP | A08 |

## Description

A webhook handler consumes the raw request body but contains no signature verification or
provider signature-header check anywhere, so any caller can forge webhook events (e.g. fake
a payment or subscription change). Any verify call or signature-header read clears it.

## Fix

Verify the event signature against the raw body with the webhook secret (e.g. stripe.webhooks.constructEvent, svix verify, or an HMAC constant-time compare) and reject on failure before using the payload.

## Examples

Bad:

```bad
app.post('/webhook', (req, res) => { const event = req.body; handle(event) })
```

Good:

```good
const event = stripe.webhooks.constructEvent(rawBody, req.headers['stripe-signature'], secret)
```

