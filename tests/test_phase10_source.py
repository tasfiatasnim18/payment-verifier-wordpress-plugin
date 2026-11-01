from pathlib import Path
root=Path(__file__).parents[1]
main=(root/'payment-verifier.php').read_text(encoding='utf-8')
gateway=(root/'includes'/'class-wc-gateway-payment-verifier.php').read_text(encoding='utf-8')

for item in ['WC_Gateway_Payment_Verifier','woocommerce_payment_gateways','_pv_provider','_pv_transaction_id','_pv_verification_status']:
    assert item in (main + gateway), f'Missing gateway feature: {item}'

for item in ['validate_fields','process_payment','payment_fields','bkash','nagad']:
    assert item in gateway, f'Missing gateway method/option: {item}'

print('PASS: Phase 10 WooCommerce gateway components are present.')
