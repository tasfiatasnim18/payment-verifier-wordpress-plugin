from pathlib import Path
text=(Path(__file__).parents[1]/'payment-verifier.php').read_text(encoding='utf-8')
required = [
    'pv_health_check',
    'payment-verifier/v1',
    '/health',
    'pv_render_integration_admin_page',
    'Staging Test Sequence',
]
for item in required:
    assert item in text, f'Missing Phase 21 integration feature: {item}'
print('PASS: Phase 21 staging integration source checks passed.')
