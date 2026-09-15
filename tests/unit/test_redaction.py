from archwright_mcp.redaction import REDACTED, is_secret_key, redact


def test_secret_key_detection_avoids_substring_false_positive() -> None:
    assert is_secret_key("wifi_psk")
    assert is_secret_key("private-key")
    assert not is_secret_key("tokenizer")
    assert not is_secret_key("secretive_mode")


def test_recursive_redaction() -> None:
    value = {
        "ssid": "Lab",
        "password": "hunter2",
        "nested": [{"api_token": "abc", "safe": "yes"}],
        "payload": b"abc",
    }
    assert redact(value) == {
        "ssid": "Lab",
        "password": REDACTED,
        "nested": [{"api_token": REDACTED, "safe": "yes"}],
        "payload": "[BYTES:3]",
    }


def test_explicit_secret_keys_are_case_insensitive() -> None:
    assert redact({"WifiValue": "secret"}, extra_secret_keys=frozenset({"wifivalue"})) == {
        "WifiValue": REDACTED
    }
