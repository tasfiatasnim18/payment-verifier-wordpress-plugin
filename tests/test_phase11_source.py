from pathlib import Path
root=Path(__file__).parents[1]
main=(root/'payment-verifier.php').read_text(encoding='utf-8')
assert 'pv_require_https' in main
assert 'request_id' in main
print('PASS: WordPress Phase 11 API hardening is present.')
