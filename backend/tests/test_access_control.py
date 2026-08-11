"""Access control, redaction and audit tests.

STRIDE: Spoofing (S), Elevation of Privilege (E), Repudiation (R),
Information Disclosure (I).
Threats: identity forged via request data; a low-privilege role reaching
clinical data or write endpoints; a user denying an action they performed.
Controls: identity read only from validated Cognito claims; deny-by-default
RBAC; field-level redaction; append-only audit log.
"""
import pytest

from conftest import make_event


# ---------------------------------------------------------------- identity --
@pytest.mark.stride("Spoofing")
def test_identity_comes_from_validated_claims(sec):
    user, role = sec.get_identity(make_event(role="Doctor", user="doctor1"))
    assert (user, role) == ("doctor1", "Doctor")


@pytest.mark.stride("Spoofing")
def test_headers_and_body_cannot_set_identity(sec):
    """Attacker-supplied headers/body must never influence the role."""
    event = make_event(role="Receptionist", user="reception1",
                       body={"role": "Admin", "cognito:groups": "Admin"})
    event["headers"] = {"X-Role": "Admin", "cognito:groups": "Admin"}
    user, role = sec.get_identity(event)
    assert role == "Receptionist"
    assert user == "reception1"


@pytest.mark.stride("Spoofing")
def test_missing_authorizer_context_yields_no_role(sec):
    user, role = sec.get_identity({})
    assert role is None
    assert user == "unknown"


@pytest.mark.stride("Elevation of Privilege")
def test_unrecognised_group_yields_no_role(sec):
    """A group invented by an attacker maps to no role, not to a default one."""
    _, role = sec.get_identity(make_event(role="SuperAdmin"))
    assert role is None


@pytest.mark.stride("Spoofing")
def test_multiple_groups_resolve_to_highest_privilege(sec):
    event = make_event(role="Receptionist,Doctor,Admin")
    _, role = sec.get_identity(event)
    assert role == "Admin"


# -------------------------------------------------------------------- RBAC --
RBAC_MATRIX = [
    # role,           action,            allowed
    ("Admin",         "patient:create",  True),
    ("Admin",         "patient:read",    True),
    ("Admin",         "patient:update",  True),
    ("Admin",         "audit:read",      True),
    ("Doctor",        "patient:create",  True),
    ("Doctor",        "patient:read",    True),
    ("Doctor",        "patient:update",  True),
    ("Doctor",        "audit:read",      False),
    ("Receptionist",  "patient:create",  False),
    ("Receptionist",  "patient:read",    True),
    ("Receptionist",  "patient:update",  False),
    ("Receptionist",  "audit:read",      False),
    (None,            "patient:read",    False),
    (None,            "patient:create",  False),
    (None,            "audit:read",      False),
]


@pytest.mark.stride("Elevation of Privilege")
@pytest.mark.parametrize("role,action,allowed", RBAC_MATRIX)
def test_rbac_matrix(sec, role, action, allowed):
    assert sec.is_allowed(role, action) is allowed


@pytest.mark.stride("Elevation of Privilege")
def test_unknown_action_is_denied_by_default(sec):
    """Deny-by-default: an action absent from the matrix is refused."""
    assert not sec.is_allowed("Admin", "patient:delete")
    assert not sec.is_allowed("Admin", "system:shutdown")


# --------------------------------------------------------------- redaction --
@pytest.mark.stride("Information Disclosure")
def test_receptionist_sees_redacted_clinical_fields(sec, valid_record):
    out = sec.redact_for("Receptionist", dict(valid_record))
    assert out["clinical_notes"] == "[REDACTED]"
    assert out["allergies"] == "[REDACTED]"


@pytest.mark.stride("Information Disclosure")
def test_receptionist_still_sees_demographics(sec, valid_record):
    out = sec.redact_for("Receptionist", dict(valid_record))
    assert out["last_name"] == "Chen"
    assert out["health_card"] == "1234567890"
    assert out["phone"] == "4165550142"


@pytest.mark.stride("Information Disclosure")
@pytest.mark.parametrize("role", ["Admin", "Doctor"])
def test_clinical_roles_see_full_record(sec, valid_record, role):
    out = sec.redact_for(role, dict(valid_record))
    assert out["clinical_notes"] == valid_record["clinical_notes"]
    assert out["allergies"] == valid_record["allergies"]


@pytest.mark.stride("Information Disclosure")
def test_redaction_does_not_mutate_the_source_record(sec, valid_record):
    sec.redact_for("Receptionist", valid_record)
    assert valid_record["clinical_notes"] == "Annual review. BP stable."


# ------------------------------------------------------------------- audit --
@pytest.mark.stride("Repudiation")
def test_audit_entry_records_who_what_when(sec):
    sec.write_audit("doctor1", "Doctor", "PATIENT_READ", "OK", patient_id="abc")
    entry = sec._test_tables["test-audit"].audit[-1]
    assert entry["user"] == "doctor1"
    assert entry["role"] == "Doctor"
    assert entry["action"] == "PATIENT_READ"
    assert entry["outcome"] == "OK"
    assert entry["patient_id"] == "abc"
    assert entry["day"] and entry["event_time"]


@pytest.mark.stride("Repudiation")
def test_denied_attempts_are_audited(sec):
    sec.write_audit("reception1", "Receptionist", "PATIENT_CREATE", "DENIED_ROLE")
    entry = sec._test_tables["test-audit"].audit[-1]
    assert entry["outcome"] == "DENIED_ROLE"


@pytest.mark.stride("Repudiation")
def test_roleless_user_is_audited_as_none(sec):
    sec.write_audit("nobody", None, "PATIENT_READ", "DENIED_NO_ROLE")
    assert sec._test_tables["test-audit"].audit[-1]["role"] == "NONE"


@pytest.mark.stride("Repudiation")
def test_audit_entries_have_unique_sort_keys(sec):
    """Two events in the same millisecond must not overwrite each other."""
    for _ in range(50):
        sec.write_audit("admin1", "Admin", "PATIENT_READ", "OK")
    keys = [e["event_time"] for e in sec._test_tables["test-audit"].audit]
    assert len(keys) == len(set(keys))


@pytest.mark.stride("Repudiation")
def test_audit_detail_is_truncated(sec):
    """A long detail string must not be able to bloat the log."""
    sec.write_audit("admin1", "Admin", "VALIDATION_REJECT", "BLOCKED", detail="x" * 5000)
    assert len(sec._test_tables["test-audit"].audit[-1]["detail"]) <= 300


# --------------------------------------------------------------- responses --
@pytest.mark.stride("Information Disclosure")
def test_error_responses_carry_security_headers(sec):
    resp = sec.error(403, "forbidden", "Not permitted.")
    headers = resp["headers"]
    assert headers["Strict-Transport-Security"].startswith("max-age=")
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Cache-Control"] == "no-store"


@pytest.mark.stride("Information Disclosure")
def test_error_body_has_no_internal_detail(sec):
    resp = sec.error(500, "server_error", "An unexpected error occurred.")
    body = resp["body"].lower()
    for leak in ("traceback", "boto", "dynamodb", "arn:aws", "lambda", "file \""):
        assert leak not in body
