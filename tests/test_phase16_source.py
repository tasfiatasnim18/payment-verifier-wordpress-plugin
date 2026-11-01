from pathlib import Path
text=(Path(__file__).parents[1]/'payment-verifier.php').read_text(encoding='utf-8')
for x in [
    'pv_register_devices_admin_page',
    'Payment Verifier Devices',
    'Generate Device API Key',
    'Rotate Key',
    'Revoke',
    'check_admin_referer',
    'manage_woocommerce',
]:
    assert x in text, f'Missing admin UI feature: {x}'
print('PASS: Phase 16 admin device management source checks passed.')
