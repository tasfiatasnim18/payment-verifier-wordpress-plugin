# Phase 34 — Idempotency & Duplicate-Payment Hardening

The plugin uses **one authoritative idempotency implementation** in
`payment-verifier.php`.

## Database table

`wp_pv_idempotency` (with the normal WordPress table prefix) contains:

- `id`
- `idempotency_key`
- `device_id`
- `request_hash`
- `response_code`
- `response_body`
- `created_at`
- `expires_at`

The database enforces a unique `idempotency_key` and indexes `device_id` and
`expires_at`.

## Contract

### Same key + same request
Return the previously stored response while it is valid. The payment
operation is not executed again.

### Same key + different request
Return `pv_idempotency_conflict` with HTTP 409. The second request is not
processed.

### Concurrent first requests
The unique database key plus `INSERT IGNORE` ensures only one request can
create the idempotency record. The other request must not create a second
record.

### Expiry
Stored idempotency records expire after the configured retention window.
Expired records are not replayed.

## Request binding

The request fingerprint is SHA-256 over the canonical request payload, and
the stored record is bound to the authenticated `device_id`.

## Staging tests

1. Send request A with a new idempotency key.
2. Send request A again with the same key → same stored result.
3. Send request B with the same key but changed amount → HTTP 409 conflict.
4. Send two requests concurrently → no duplicate confirmation.
5. Force a client timeout after processing.
6. Retry with the same key → original result, no duplicate payment completion.
