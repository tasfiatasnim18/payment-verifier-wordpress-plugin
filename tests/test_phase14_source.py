from pathlib import Path
text=(Path(__file__).parents[1]/'payment-verifier.php').read_text(encoding='utf-8')
for x in ['pv_sync_orders', '/orders', 'pending', 'on-hold', '_pv_transaction_id', 'server_time']:
    assert x in text, f'Missing order sync feature: {x}'
print('PASS: Phase 14 order synchronization endpoint is present.')
