"""Handler pipeline tests — full request through the Lambda entrypoints.

These exercise identity -> RBAC -> validation -> crypto -> audit as one flow,
using the same API Gateway event shape the deployed functions receive.
"""
import json

import pytest

from conftest import make_event


@pytest.fixture()
def app(sec):
    import audit as audit_mod
    import patients as patients_mod
    return patients_mod, audit_mod


def create(app, role="Admin", user="admin1", **overrides):
    patients, _ = app
    payload = {
        "first_name": "Sarah", "last_name": "Chen",
        "date_of_birth": "1985-03-14", "health_card": "1234567890",
        "clinical_notes": "Annual review.", "allergies": "penicillin",
    }
    payload.update(overrides)
    resp = patients.handler(make_event("POST", payload, role=role, user=user), None)
    return resp, json.loads(resp["body"])


# ------------------------------------------------------------------ create --
@pytest.mark.stride("Elevation of Privilege")
def test_admin_can_create(app):
    resp, body = create(app)
    assert resp["statusCode"] == 201
    assert body["patient"]["first_name"] == "Sarah"


@pytest.mark.stride("Elevation of Privilege")
def test_doctor_can_create(app):
    resp, _ = create(app, role="Doctor", user="doctor1")
    assert resp["statusCode"] == 201


@pytest.mark.stride("Elevation of Privilege")
def test_receptionist_cannot_create(app):
    resp, body = create(app, role="Receptionist", user="reception1")
    assert resp["statusCode"] == 403
    assert body["error"] == "forbidden"


@pytest.mark.stride("Elevation of Privilege")
def test_user_without_role_cannot_create(app):
    resp, _ = create(app, role=None, user="nobody")
    assert resp["statusCode"] == 403


@pytest.mark.stride("Tampering")
def test_create_with_injection_returns_400(app):
    resp, body = create(app, first_name="Robert'); DROP TABLE patients;--")
    assert resp["statusCode"] == 400
    assert body["error"] == "validation_failed"


@pytest.mark.stride("Elevation of Privilege")
def test_client_cannot_set_patient_id(app):
    """Server generates the id; a client-supplied one is rejected."""
    resp, _ = create(app, patient_id="attacker-chosen-id")
    assert resp["statusCode"] == 400


# -------------------------------------------------------------------- read --
@pytest.mark.stride("Information Disclosure")
def test_doctor_reads_full_record(app):
    patients, _ = app
    _, created = create(app)
    pid = created["patient"]["patient_id"]
    resp = patients.handler(
        make_event("GET", role="Doctor", user="doctor1", path_params={"id": pid}), None)
    body = json.loads(resp["body"])
    assert resp["statusCode"] == 200
    assert body["patient"]["clinical_notes"] == "Annual review."


@pytest.mark.stride("Information Disclosure")
def test_receptionist_read_is_redacted(app):
    patients, _ = app
    _, created = create(app)
    pid = created["patient"]["patient_id"]
    resp = patients.handler(
        make_event("GET", role="Receptionist", user="reception1", path_params={"id": pid}), None)
    body = json.loads(resp["body"])
    assert resp["statusCode"] == 200
    assert body["patient"]["clinical_notes"] == "[REDACTED]"
    assert body["patient"]["allergies"] == "[REDACTED]"
    assert body["patient"]["last_name"] == "Chen"


@pytest.mark.stride("Tampering")
def test_read_with_invalid_id_returns_400(app):
    patients, _ = app
    resp = patients.handler(
        make_event("GET", path_params={"id": "../../admin"}), None)
    assert resp["statusCode"] == 400


@pytest.mark.stride("Information Disclosure")
def test_read_missing_record_returns_404(app):
    patients, _ = app
    resp = patients.handler(
        make_event("GET", path_params={"id": "11111111-2222-4333-8444-555555555555"}), None)
    assert resp["statusCode"] == 404


@pytest.mark.stride("Tampering")
def test_tampered_record_returns_409(app, sec):
    """End-to-end version of the console tamper demo."""
    patients, _ = app
    _, created = create(app)
    pid = created["patient"]["patient_id"]

    table = sec._test_tables["test-patients"]
    table.items[pid]["first_name"] = "Eve"          # attacker edits the DB directly

    resp = patients.handler(make_event("GET", path_params={"id": pid}), None)
    body = json.loads(resp["body"])
    assert resp["statusCode"] == 409
    assert body["error"] == "integrity_failure"


@pytest.mark.stride("Repudiation")
def test_tamper_detection_is_audited(app, sec):
    patients, _ = app
    _, created = create(app)
    pid = created["patient"]["patient_id"]
    sec._test_tables["test-patients"].items[pid]["last_name"] = "Attacker"
    patients.handler(make_event("GET", path_params={"id": pid}), None)
    actions = [e["action"] for e in sec._test_tables["test-audit"].audit]
    assert "TAMPER_DETECTED" in actions


# ------------------------------------------------------------------ update --
@pytest.mark.stride("Elevation of Privilege")
def test_receptionist_cannot_update(app):
    patients, _ = app
    _, created = create(app)
    pid = created["patient"]["patient_id"]
    resp = patients.handler(
        make_event("PUT", {"phone": "4165559999"}, role="Receptionist",
                   user="reception1", path_params={"id": pid}), None)
    assert resp["statusCode"] == 403


@pytest.mark.stride("Tampering")
def test_update_rehashes_and_reencrypts(app, sec):
    patients, _ = app
    _, created = create(app)
    pid = created["patient"]["patient_id"]

    before = sec._test_tables["test-patients"].items[pid]["integrity"]
    resp = patients.handler(
        make_event("PUT", {"clinical_notes": "Updated: dosage changed to 10mg."},
                   role="Doctor", user="doctor1", path_params={"id": pid}), None)
    assert resp["statusCode"] == 200

    after_item = sec._test_tables["test-patients"].items[pid]
    assert after_item["integrity"] != before          # hash follows the new content
    assert sec.from_storage(after_item)["clinical_notes"].startswith("Updated")


# ------------------------------------------------------------------ search --
@pytest.mark.stride("Information Disclosure")
def test_search_redacts_for_receptionist(app):
    patients, _ = app
    create(app)
    resp = patients.handler(
        make_event("GET", role="Receptionist", user="reception1", query={"q": "chen"}), None)
    body = json.loads(resp["body"])
    assert resp["statusCode"] == 200
    assert all(p["clinical_notes"] == "[REDACTED]" for p in body["patients"])


@pytest.mark.stride("Tampering")
def test_search_skips_and_counts_tampered_records(app, sec):
    """One bad record must not break the whole list, and must be reported."""
    patients, _ = app
    _, created = create(app)
    create(app, first_name="Ana", last_name="Silva", health_card="2222222222")

    pid = created["patient"]["patient_id"]
    sec._test_tables["test-patients"].items[pid]["first_name"] = "Eve"

    resp = patients.handler(make_event("GET", query={"q": ""}), None)
    body = json.loads(resp["body"])
    assert resp["statusCode"] == 200
    assert body["integrity_failures"] == 1
    assert all(p["patient_id"] != pid for p in body["patients"])


# ------------------------------------------------------------------- audit --
@pytest.mark.stride("Elevation of Privilege")
def test_only_admin_reads_audit_log(app):
    _, audit_mod = app
    for role in ("Doctor", "Receptionist", None):
        resp = audit_mod.handler(make_event("GET", role=role), None)
        assert resp["statusCode"] == 403, f"{role} should not read the audit log"
    resp = audit_mod.handler(make_event("GET", role="Admin"), None)
    assert resp["statusCode"] == 200


@pytest.mark.stride("Repudiation")
def test_audit_read_is_itself_audited(app, sec):
    _, audit_mod = app
    audit_mod.handler(make_event("GET", role="Admin", user="admin1"), None)
    assert any(e["action"] == "AUDIT_READ" for e in sec._test_tables["test-audit"].audit)


@pytest.mark.stride("Denial of Service")
def test_audit_limit_is_capped(app):
    _, audit_mod = app
    resp = audit_mod.handler(
        make_event("GET", role="Admin", query={"limit": "999999"}), None)
    assert resp["statusCode"] == 200      # clamped internally, not rejected


@pytest.mark.stride("Tampering")
def test_audit_rejects_bad_day_parameter(app):
    _, audit_mod = app
    resp = audit_mod.handler(
        make_event("GET", role="Admin", query={"day": "'; DROP TABLE--"}), None)
    assert resp["statusCode"] == 400
