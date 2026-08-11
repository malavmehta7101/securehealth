"""Encryption and integrity tests.

STRIDE: Information Disclosure (I) and Tampering (T).
Threats: PHI exposed from a stolen table/backup; a record silently altered by
an attacker or insider with direct database access.
Controls: AES-256-GCM via KMS with per-record encryption context;
SHA-256 hash over the canonical plaintext, verified on every read.
"""
import json

import pytest


def stored(sec, record):
    return sec.to_storage(record)


@pytest.fixture()
def record(sec, valid_record):
    return {"patient_id": sec.new_patient_id(), **valid_record,
            "created_at": sec.now_iso(), "updated_at": sec.now_iso()}


# ------------------------------------------------------------- encryption --
@pytest.mark.stride("Information Disclosure")
def test_clinical_fields_are_not_stored_in_plaintext(sec, record):
    item = stored(sec, record)
    blob = json.dumps(item, default=str)
    assert "Annual review" not in blob
    assert "penicillin" not in blob
    assert "clinical_notes" not in item      # only the _enc variant is persisted
    assert "allergies" not in item


@pytest.mark.stride("Information Disclosure")
def test_encrypted_fields_are_present_and_opaque(sec, record):
    item = stored(sec, record)
    assert item["clinical_notes_enc"]
    assert item["allergies_enc"]
    assert item["clinical_notes_enc"] != record["clinical_notes"]


@pytest.mark.stride("Information Disclosure")
def test_demographics_remain_queryable(sec, record):
    """Non-clinical fields stay in clear text so search works by design."""
    item = stored(sec, record)
    assert item["last_name"] == "Chen"
    assert item["health_card"] == "1234567890"


@pytest.mark.stride("Information Disclosure")
def test_roundtrip_returns_original_plaintext(sec, record):
    back = sec.from_storage(stored(sec, record))
    assert back["clinical_notes"] == record["clinical_notes"]
    assert back["allergies"] == record["allergies"]


@pytest.mark.stride("Information Disclosure")
def test_empty_clinical_fields_handled(sec, record):
    record["clinical_notes"] = ""
    record["allergies"] = ""
    back = sec.from_storage(stored(sec, record))
    assert back["clinical_notes"] == ""


@pytest.mark.stride("Information Disclosure")
def test_ciphertext_bound_to_its_patient(sec, record):
    """A blob copied onto another record must not decrypt.

    Without the encryption context an attacker could move one patient's
    encrypted notes onto another patient's record.
    """
    blob = sec.encrypt_field("Confidential note", record["patient_id"])
    with pytest.raises(Exception):
        sec.decrypt_field(blob, "11111111-2222-4333-8444-555555555555")


# -------------------------------------------------------------- integrity --
@pytest.mark.stride("Tampering")
def test_integrity_hash_is_deterministic(sec, record):
    assert sec.compute_integrity(record) == sec.compute_integrity(dict(record))


@pytest.mark.stride("Tampering")
def test_integrity_hash_is_sha256_hex(sec, record):
    h = sec.compute_integrity(record)
    assert len(h) == 64 and int(h, 16) >= 0


@pytest.mark.stride("Tampering")
@pytest.mark.parametrize("field,value", [
    ("first_name", "Eve"),
    ("last_name", "Attacker"),
    ("health_card", "9999999999"),
    ("date_of_birth", "1970-01-01"),
])
def test_tamper_with_plaintext_field_is_detected(sec, record, field, value):
    """The demo attack: edit a record directly in the DynamoDB console."""
    item = stored(sec, record)
    item[field] = value
    with pytest.raises(sec.IntegrityError):
        sec.from_storage(item)


@pytest.mark.stride("Tampering")
def test_tamper_with_ciphertext_is_detected(sec, record):
    """Swapping an encrypted blob for a valid one from the same record."""
    item = stored(sec, record)
    item["allergies_enc"] = sec.encrypt_field("none", record["patient_id"])
    with pytest.raises(sec.IntegrityError):
        sec.from_storage(item)


@pytest.mark.stride("Tampering")
def test_forged_integrity_hash_is_detected(sec, record):
    """An attacker who edits the record but cannot recompute a matching hash."""
    item = stored(sec, record)
    item["first_name"] = "Eve"
    item["integrity"] = "0" * 64
    with pytest.raises(sec.IntegrityError):
        sec.from_storage(item)


@pytest.mark.stride("Tampering")
def test_missing_integrity_hash_is_detected(sec, record):
    item = stored(sec, record)
    del item["integrity"]
    with pytest.raises(sec.IntegrityError):
        sec.from_storage(item)


@pytest.mark.stride("Tampering")
def test_restoring_the_original_value_passes_again(sec, record):
    """Verification is deterministic, not a permanent failure state."""
    item = stored(sec, record)
    original = item["first_name"]
    item["first_name"] = "Eve"
    with pytest.raises(sec.IntegrityError):
        sec.from_storage(item)
    item["first_name"] = original
    assert sec.from_storage(item)["first_name"] == original


@pytest.mark.stride("Tampering")
def test_hash_is_case_sensitive(sec, record):
    """'5mg' vs '50mg' matters in a medical record - the check is exact."""
    item = stored(sec, record)
    item["first_name"] = record["first_name"].lower()
    with pytest.raises(sec.IntegrityError):
        sec.from_storage(item)
