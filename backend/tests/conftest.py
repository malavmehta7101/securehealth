"""Shared pytest fixtures for the SecureHealth test suite.

Two layers:
  * unit        - no AWS calls; boto3 is stubbed so the security logic
                  (validation, crypto, integrity, RBAC) is tested in isolation.
  * integration - real HTTP calls against the deployed API with real Cognito
                  tokens. Skipped automatically when tokens are not configured.
"""
import base64
import json
import os
import sys

import pytest

HANDLERS = os.path.join(os.path.dirname(__file__), "..", "src", "handlers")
sys.path.insert(0, os.path.abspath(HANDLERS))

os.environ.setdefault("PATIENTS_TABLE", "test-patients")
os.environ.setdefault("AUDIT_TABLE", "test-audit")
os.environ.setdefault("KMS_KEY_ID", "test-key")


# ---------------------------------------------------------------- unit ------
class FakeKMS:
    """Stand-in for AWS KMS.

    Encryption context is echoed into the blob and checked on decrypt, so the
    tests can prove the context binding actually rejects a mismatched record.
    """

    def encrypt(self, KeyId, Plaintext, EncryptionContext):
        ctx = json.dumps(EncryptionContext, sort_keys=True).encode()
        return {"CiphertextBlob": b"ENC|" + base64.b64encode(ctx) + b"|" + Plaintext}

    def decrypt(self, CiphertextBlob, EncryptionContext):
        _, ctx_b64, pt = CiphertextBlob.split(b"|", 2)
        expected = json.dumps(EncryptionContext, sort_keys=True).encode()
        if base64.b64decode(ctx_b64) != expected:
            raise RuntimeError("InvalidCiphertextException: encryption context mismatch")
        return {"Plaintext": pt}


class FakeTable:
    def __init__(self):
        self.items = {}
        self.audit = []

    def put_item(self, Item):
        key = Item.get("patient_id") or Item.get("event_time")
        self.items[key] = dict(Item)
        if "action" in Item:
            self.audit.append(Item)

    def get_item(self, Key):
        pid = Key["patient_id"]
        return {"Item": dict(self.items[pid])} if pid in self.items else {}

    def scan(self, **_):
        return {"Items": [dict(v) for v in self.items.values()]}

    def query(self, **_):
        return {"Items": list(self.audit)}


@pytest.fixture()
def sec(monkeypatch):
    """Import the shared security module with AWS stubbed out."""
    import boto3

    tables = {"test-patients": FakeTable(), "test-audit": FakeTable()}

    class FakeResource:
        def Table(self, name):
            return tables.setdefault(name, FakeTable())

    monkeypatch.setattr(boto3, "resource", lambda *a, **k: FakeResource())
    monkeypatch.setattr(boto3, "client", lambda *a, **k: FakeKMS())

    for mod in ("common", "patients", "audit", "health"):
        sys.modules.pop(mod, None)

    import common

    common._test_tables = tables          # exposed so tests can inspect stored items
    return common


@pytest.fixture()
def valid_record():
    return {
        "first_name": "Sarah",
        "last_name": "Chen",
        "date_of_birth": "1985-03-14",
        "health_card": "1234567890",
        "email": "s.chen@example.ca",
        "phone": "4165550142",
        "clinical_notes": "Annual review. BP stable.",
        "allergies": "penicillin",
    }


def make_event(method="GET", body=None, role="Admin", user="tester",
               path_params=None, query=None):
    """Build an API Gateway proxy event with Cognito authorizer claims."""
    claims = {"cognito:username": user}
    if role:
        claims["cognito:groups"] = role
    return {
        "httpMethod": method,
        "body": json.dumps(body) if body is not None else None,
        "pathParameters": path_params,
        "queryStringParameters": query,
        "requestContext": {"authorizer": {"claims": claims}},
    }


# --------------------------------------------------------- integration -----
def pytest_configure(config):
    config.addinivalue_line("markers", "integration: hits the deployed API (needs tokens)")
    config.addinivalue_line("markers", "stride(threat): STRIDE category this test validates")


@pytest.fixture(scope="session")
def api_url():
    url = os.environ.get("SECUREHEALTH_API_URL")
    if not url:
        pytest.skip("SECUREHEALTH_API_URL not set - skipping integration tests")
    return url.rstrip("/")


def _token(var):
    tok = os.environ.get(var)
    if not tok:
        pytest.skip(f"{var} not set - skipping integration test")
    return tok


@pytest.fixture(scope="session")
def admin_token():
    return _token("SECUREHEALTH_ADMIN_TOKEN")


@pytest.fixture(scope="session")
def doctor_token():
    return _token("SECUREHEALTH_DOCTOR_TOKEN")


@pytest.fixture(scope="session")
def reception_token():
    return _token("SECUREHEALTH_RECEPTION_TOKEN")
