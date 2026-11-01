# Phase 31 — WordPress API & Database Hardening

## Completed

- Inventoried REST route registrations.
- Reviewed REST permission callbacks.
- Inventoried direct `$wpdb` usage.
- Reviewed dynamic SQL expressions for parameterization.
- Reviewed request parameter access.
- Reviewed potential database-error disclosure.
- Added a centralized API error helper.
- Added correlation-ID normalization for Payment Verifier REST responses.
- Restricted exposed error metadata to safe fields.

## Security principle

The API must fail closed:
- unauthenticated devices are rejected;
- device/store scope is enforced;
- request values are validated;
- SQL parameters are bound rather than interpolated;
- internal database/exception details are never returned;
- every API request can be correlated without exposing secrets.

## Remaining

A real staging environment is still required for dynamic tests:
- unauthorized request
- revoked device
- wrong store
- malformed payload
- SQL edge cases
- duplicate transaction
- idempotency conflict
- rate/abuse behavior
