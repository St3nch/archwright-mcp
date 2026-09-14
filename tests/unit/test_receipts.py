from archwright_mcp.receipts import ReceiptStore


def test_receipt_persists_and_redacts(tmp_path):
    store = ReceiptStore(tmp_path / "receipts", "target")
    rid = store.new_id()
    receipt = store.persist(receipt_id=rid, tool="wifi_connect", started_at="2026-01-01T00:00:00+00:00", status="ok", request={"ssid": "x", "passphrase": "do-not-store"}, result={"exit_code": 0}, identity_digest="abc")
    assert receipt["request"]["passphrase"] == "<redacted>"
    loaded = store.get(rid)
    assert loaded["receipt_id"] == rid
    assert loaded["request"]["passphrase"] == "<redacted>"
