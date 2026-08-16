"""Ingest validation tests — the device zone is untrusted input like any other."""
import json, os, sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
os.environ.update(TELEMETRY_TABLE="t", ALERT_TOPIC="arn:x", MIN_SAFE_C="2", MAX_SAFE_C="8")


@pytest.fixture()
def mod(monkeypatch):
    import boto3
    stored, published = [], []

    class T:
        def put_item(self, Item): stored.append(Item)
    class R:
        def Table(self, n): return T()
    class S:
        def publish(self, **kw): published.append(kw)

    monkeypatch.setattr(boto3, "resource", lambda *a, **k: R())
    monkeypatch.setattr(boto3, "client", lambda *a, **k: S())
    sys.modules.pop("ingest", None)
    import ingest
    ingest._stored, ingest._published = stored, published
    return ingest


def ev(**kw):
    base = {"device_id": "securehealth-fridge-01", "temperature_c": 4.5, "humidity_pct": 44.0}
    base.update(kw)
    return base


def test_valid_reading_stored(mod):
    assert mod.handler(ev(), None)["status"] == "ok"
    assert mod._stored[-1]["in_range"] is True


def test_out_of_range_alerts(mod):
    r = mod.handler(ev(temperature_c=11.4), None)
    assert r["in_range"] is False
    assert mod._published, "an out-of-range reading must raise an alert"


def test_below_range_alerts(mod):
    assert mod.handler(ev(temperature_c=-1.0), None)["in_range"] is False


@pytest.mark.parametrize("bad", [
    {"temperature_c": "not-a-number"},
    {"temperature_c": None},
    {"temperature_c": 500},          # physically implausible: forged or faulty
    {"temperature_c": -99},
])
def test_malformed_payloads_rejected(mod, bad):
    assert mod.handler(ev(**bad), None)["status"] == "rejected"


def test_missing_temperature_rejected(mod):
    e = ev(); del e["temperature_c"]
    assert mod.handler(e, None)["status"] == "rejected"


def test_missing_device_id_rejected(mod):
    assert mod.handler(ev(device_id=""), None)["status"] == "rejected"


def test_oversized_device_id_rejected(mod):
    assert mod.handler(ev(device_id="x" * 200), None)["status"] == "rejected"


def test_implausible_humidity_rejected(mod):
    assert mod.handler(ev(humidity_pct=999), None)["status"] == "rejected"


def test_rejected_reading_is_never_stored(mod):
    mod.handler(ev(temperature_c="bogus"), None)
    assert not mod._stored


def test_device_id_comes_from_topic_not_payload(mod):
    """The rule sets device_id from the topic; a payload field cannot override it."""
    mod.handler(ev(device_id="securehealth-fridge-01"), None)
    assert mod._stored[-1]["device_id"] == "securehealth-fridge-01"
