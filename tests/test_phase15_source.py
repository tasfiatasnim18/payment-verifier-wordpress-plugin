from pathlib import Path
text=(Path(__file__).parents[1]/'payment-verifier.php').read_text(encoding='utf-8')
for x in ['pv_devices', 'pv_provision_device', 'pv_device_permission', 'X-PV-Device-ID', 'api_key_hash', 'revoked']:
    assert x in text, f'Missing Phase 15 feature: {x}'
print('PASS: Phase 15 device authentication/scoping source checks passed.')
