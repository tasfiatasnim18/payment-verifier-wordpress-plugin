# Phase 33 — WooCommerce Business Logic & Failure Matrix

| Scenario | Required result |
|---|---|
| Correct provider + amount + transaction + scope | Verify and complete order |
| Wrong amount | Reject; do not complete |
| Wrong store | Reject; do not complete |
| Wrong device | Reject; do not complete |
| Duplicate transaction | Reject; do not complete |
| Idempotency replay, same payload | Return original result |
| Idempotency conflict, different payload | Reject |
| Missing transaction ID | Reject |
| WooCommerce unavailable | Reject safely |
| Order not found | Reject safely |
| Already completed order | Return completed state; never regress |
| Cancelled/refunded/failed order | Reject transition |
| Incomplete verification payload | Reject |
| Internal DB/API error | Return safe error; do not expose internals |

## Transition invariant

`payment_complete()` must only happen after an explicit verified payment
result has passed the provider, amount, transaction, store, device, and
idempotency checks.

A failure at any earlier step must leave the WooCommerce order uncompleted.
