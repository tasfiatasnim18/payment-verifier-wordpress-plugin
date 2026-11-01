from pathlib import Path

root = Path(__file__).parents[1]
main = (root / "payment-verifier.php").read_text(encoding="utf-8")
binding = (root / "includes" / "order-binding.php").read_text(encoding="utf-8")

required_main = [
    "'reference'",
    "'_pv_payment_reference'",
    "wc_get_orders(array(",
    "_pv_transaction_id",
    "pv_order_amount_mismatch",
    "pv_order_transaction_mismatch",
    "pv_replay",
    "hash_equals",
]

for item in required_main:
    assert item in main, f"Missing strict binding feature: {item}"

assert "woocommerce_checkout_create_order" in binding
assert "_pv_provider" in binding
assert "_pv_transaction_id" in binding

print("PASS: Phase 9 reference binding and checkout binding are present.")
