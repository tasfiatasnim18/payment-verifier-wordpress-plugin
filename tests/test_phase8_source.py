from pathlib import Path
src=Path(__file__).parents[1]/'payment-verifier.php'
text=src.read_text(encoding='utf-8')
for item in ['pv_admin_dashboard','pv_admin_devices','pv_admin_payments','pv_admin_logs','wp_generate_password','pv_payments','pv_devices','pv_audit_logs','woocommerce_admin_order_data_after_order_details']:
    assert item in text, f'Missing: {item}'
print('PASS: Phase 8 admin components present.')
