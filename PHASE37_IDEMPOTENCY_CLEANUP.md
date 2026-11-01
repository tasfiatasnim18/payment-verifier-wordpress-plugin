# Idempotency Implementation Cleanup

The release candidate previously contained an unused secondary idempotency
helper whose schema did not match the active plugin schema.

This revision removes that redundant helper and its activation hook. The
existing `payment-verifier.php` implementation remains the single source of
truth for idempotency and uses the already-created `wp_pv_idempotency` table.

No database table should be dropped or manually recreated during staging.
