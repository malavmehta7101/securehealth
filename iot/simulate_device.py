"""SecureHealth equipment monitor - device simulator.

Publishes the same payload, to the same topic, over the same mutually
authenticated TLS connection as the ESP32 firmware. The cloud side cannot tell
the difference, which is the point: the security architecture is identical
whether the reading comes from a sensor or from this script.

Usage:
    pip install paho-mqtt
    python simulate_device.py --endpoint <iot-endpoint> --certs ./certs

    --scenario normal    steady readings inside the safe range (default)
    --scenario excursion drifts out of range to trigger the alarm
    --scenario spoof     sends a malformed payload to show it being rejected

Get the endpoint with:
    aws iot describe-endpoint --endpoint-type iot:Data-ATS --region ca-central-1
"""
import argparse
import json
import random
import ssl
import sys
import time
from datetime import datetime, timezone

try:
    import paho.mqtt.client as mqtt
except ImportError:
    sys.exit("Install the MQTT client first:  pip install paho-mqtt")

DEVICE = "securehealth-fridge-01"
TOPIC = f"securehealth/telemetry/{DEVICE}"


def build_client(endpoint, certs, device):
    client = mqtt.Client(client_id=device, protocol=mqtt.MQTTv311)

    # Mutual TLS: the CA proves AWS to us, the certificate and private key
    # prove this device to AWS. Neither side is taken on trust.
    client.tls_set(
        ca_certs=f"{certs}/AmazonRootCA1.pem",
        certfile=f"{certs}/device-certificate.pem.crt",
        keyfile=f"{certs}/device-private.pem.key",
        tls_version=ssl.PROTOCOL_TLSv1_2,
    )

    def on_connect(_c, _u, _f, rc):
        if rc == 0:
            print(f"Connected to {endpoint} as {device}")
        else:
            print(f"Connection refused (code {rc}) - check the certificate and IoT policy")

    client.on_connect = on_connect
    client.connect(endpoint, 8883, keepalive=60)
    return client


def reading(scenario, tick):
    """Produce the payload the ESP32 firmware would send."""
    if scenario == "excursion":
        # A door left open: temperature climbs steadily out of the safe band.
        temperature = 4.0 + tick * 1.1
    elif scenario == "spoof":
        # A forged or corrupted payload. The ingest function rejects this and
        # records a TELEMETRY_REJECTED event rather than storing it.
        return {"temperature_c": "not-a-number", "humidity_pct": 999}
    else:
        temperature = round(random.uniform(3.4, 5.2), 1)

    return {
        "temperature_c": round(temperature, 1),
        "humidity_pct": round(random.uniform(38, 52), 1),
        "firmware": "sim-1.0",
        "sent_at": datetime.now(timezone.utc).isoformat(),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", required=True, help="AWS IoT data endpoint")
    ap.add_argument("--certs", default="./certs", help="directory holding the device certificate")
    ap.add_argument("--device", default=DEVICE)
    ap.add_argument("--scenario", default="normal", choices=["normal", "excursion", "spoof"])
    ap.add_argument("--interval", type=float, default=5.0, help="seconds between readings")
    ap.add_argument("--count", type=int, default=0, help="readings to send (0 = run until stopped)")
    args = ap.parse_args()

    topic = f"securehealth/telemetry/{args.device}"
    client = build_client(args.endpoint, args.certs, args.device)
    client.loop_start()
    time.sleep(1)

    tick = 0
    try:
        while args.count == 0 or tick < args.count:
            payload = reading(args.scenario, tick)
            client.publish(topic, json.dumps(payload), qos=1)
            temp = payload.get("temperature_c")
            flag = "" if isinstance(temp, (int, float)) and 2 <= temp <= 8 else "   <-- outside safe range"
            print(f"  {topic}  {temp} C{flag}")
            tick += 1
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
