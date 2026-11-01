# Payment Verifier — Release Candidate Checklist

## Static gate
- [x] Plugin bootstrap present
- [x] WordPress direct-access guards
- [x] REST permission architecture reviewed
- [x] Prepared SQL usage
- [x] WP_Error failure paths
- [x] Capability checks
- [x] Admin request protection
- [x] Idempotency layer
- [x] Order transition guard
- [x] Transaction tracking
- [x] Audit/correlation support
- [x] WooCommerce integration
- [x] Staging runbook
- [x] Failure matrix
- [x] Database integrity documentation
- [x] Idempotency documentation
- [x] No obvious hard-coded production credentials
- [x] Package cleanliness

## Dynamic gate — staging required
- [ ] Activate plugin on staging
- [ ] Run database migrations/activation
- [ ] Run diagnostics
- [ ] Create controlled WooCommerce order
- [ ] Verify successful payment
- [ ] Verify wrong amount rejection
- [ ] Verify wrong store rejection
- [ ] Verify wrong device rejection
- [ ] Verify duplicate transaction rejection
- [ ] Verify idempotency replay
- [ ] Verify idempotency conflict
- [ ] Verify order-state protection
- [ ] Verify audit trail
- [ ] Verify Android client against staging API

## Production gate
Production credentials and live payment traffic remain disabled until all
dynamic staging tests pass.
