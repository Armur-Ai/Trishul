# VIBE-WEBHOOK-002: Client-trusted payment/access value from request body

A handler trusts a price/plan/role value from req.body.

## Metadata

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Confidence | 0.50 |
| Maturity | stable |
| Mode | comment |
| Languages | javascript, typescript, python |
| File kinds | source |
| CWE | CWE-602 |
| OWASP | A04 |

## Description

A payment/checkout/order or access-control handler reads a sensitive value
(amount/price/total/plan/role/isAdmin) straight from the client request body and acts on
it, so a client can tamper with the price they pay or the privilege they receive.

## Fix

Enforce the value server-side — look up the price/amount from the product/order record by id, and derive roles/plan from the authenticated session, never from request input.

## Examples

Bad:

```bad
await stripe.charges.create({ amount: req.body.amount })
```

Good:

```good
const order = await db.order.findUnique({ where: { id } }); await stripe.charges.create({ amount: order.amount })
```

