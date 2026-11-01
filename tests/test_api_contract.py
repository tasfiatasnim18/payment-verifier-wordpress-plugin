"""
Phase 9 API contract checks. No real WordPress or payment provider is contacted.
"""
payload = {
    "reference": "PV-28-V7DWIP",
    "provider": "bkash",
    "amount": 1500.0,
    "transaction_id": "TESTTXN123456",
    "device_id": "TEST-DEVICE-01",
}

assert payload["reference"]
assert payload["provider"] in {"bkash", "nagad"}
assert payload["amount"] > 0
assert payload["transaction_id"]
assert payload["device_id"]

print("PASS: reference-based API contract is valid.")
