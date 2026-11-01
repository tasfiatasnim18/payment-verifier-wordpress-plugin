from pathlib import Path
text=(Path(__file__).parents[1]/'payment-verifier.php').read_text(encoding='utf-8')
for x in [
    'pv_scoped_device_permission',
    'pv_device_unassigned',
    'store_id',
    'store_key',
    'pv_device_stores',
]:
    assert x in text, f'Missing integration/scope contract: {x}'
print('PASS: Phase 19 WordPress integration source checks passed.')
