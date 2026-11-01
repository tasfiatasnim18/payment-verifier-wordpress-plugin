from pathlib import Path
text=(Path(__file__).parents[1]/'payment-verifier.php').read_text(encoding='utf-8')
required = [
    'pv_idempotency',
    'idempotency-key',
    'pv_idempotency_conflict',
    'pv_verification_rate_limit',
    'pv_store_scope_violation',
    'pv_provider_mismatch',
    'pv_transaction_mismatch',
    'pv_amount_mismatch',
    'UNIQUE KEY transaction_id',
    'concurrent_duplicate',
    'already_verified',
]
for item in required:
    assert item in text, f'Missing Phase 20 hardening feature: {item}'
print('PASS: Phase 20 hardening source checks passed.')
