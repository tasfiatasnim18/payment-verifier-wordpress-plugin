# Payment Verifier — WordPress Staging Runbook

## 1. Install
1. Back up the staging database.
2. Upload the plugin ZIP.
3. Activate Payment Verifier.
4. Open **WooCommerce → Payment Verifier Diagnostics**.

## 2. Preflight
All checks should show PASS:
- WordPress
- WooCommerce
- Audit log table
- Devices table
- Stores table
- Device/store scope table
- HTTPS
- Correlation ID support
- Audit support

## 3. Controlled verification
Use only staging orders and staging credentials.

Record:
- order ID
- store ID
- device ID
- transaction ID
- correlation ID
- final order status

## 4. Negative tests
Verify rejection for:
- wrong amount
- wrong store
- wrong transaction ID
- revoked device
- duplicate transaction
- idempotency conflict

## 5. Audit
Open **WooCommerce → Payment Verifier Audit** and verify the correlation ID
can be followed from request to final outcome.

## 6. Production gate
Do not enable real payment traffic until:
- HTTPS is confirmed
- staging tests pass
- Android APK build passes
- Android runtime smoke test passes
- production credentials are generated separately
- rollback procedure is documented
