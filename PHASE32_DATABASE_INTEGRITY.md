# Phase 32 — Database & WooCommerce Integrity

## Completed

- Inventoried custom database schema creation.
- Reviewed WooCommerce order API usage.
- Reviewed order status/payment mutation points.
- Verified transaction/order/store/device tracking references.
- Verified idempotency-related implementation references.
- Added a read-only database integrity checker.

## Integrity checks

The staging checker validates:

- required Payment Verifier tables exist;
- WooCommerce is available;
- `WC_Order` is available;
- required table columns exist;
- the checker itself performs no UPDATE/DELETE operations.

## Business invariant

A successful payment verification must preserve:

1. correct WooCommerce order;
2. correct store scope;
3. correct device scope;
4. correct provider;
5. correct amount;
6. unique transaction;
7. idempotent request behavior;
8. auditable correlation ID;
9. deterministic order-state transition.

## Remaining

Run these checks against the real staging database and WooCommerce instance.
The static audit cannot prove production database constraints or transaction
behavior without executing against the actual environment.
