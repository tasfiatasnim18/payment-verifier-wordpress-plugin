from pathlib import Path
text=(Path(__file__).parents[1]/'payment-verifier.php').read_text(encoding='utf-8')
required = [
    'pv_audit_table',
    'pv_audit',
    'pv_request_correlation_id',
    'X-PV-Correlation-ID',
    'pv_render_audit_admin_page',
    'duration_ms',
    'error_code',
]
for item in required:
    assert item in text, f'Missing Phase 22 observability feature: {item}'
print('PASS: Phase 22 observability source checks passed.')
