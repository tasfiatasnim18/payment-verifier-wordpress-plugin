from pathlib import Path
text=(Path(__file__).parents[1]/'payment-verifier.php').read_text(encoding='utf-8')
for x in [
    'pv_stores',
    'pv_device_stores',
    'pv_scoped_device_permission',
    'pv_device_unassigned',
    'store_id',
    'pv_create_store',
    'pv_assign_device_to_store',
]:
    assert x in text, f'Missing Phase 18 scope feature: {x}'
print('PASS: Phase 18 explicit store scope source checks passed.')
