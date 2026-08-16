# SecureHealth IoT Extension — Secure Equipment Monitoring

Built **after** the assessed scope was complete. The graded application stack
(`securehealth`) is untouched: this deploys as a separate stack that can be
created and deleted without affecting it.

## What it does

An ESP32 with a DHT11 sensor monitors the temperature of a vaccine
refrigerator, shows the reading on an OLED, and publishes it to AWS IoT Core
over mutually authenticated TLS. IoT Core routes readings to a Lambda that
validates them, stores them in DynamoDB, and raises an SNS alert when a
reading leaves the 2–8 °C safe range.

A Python simulator publishes identical payloads over the same authenticated
channel, so the system is fully demonstrable without hardware.

## Security design

| Concern | Control |
|---|---|
| Device impersonation (Spoofing) | Per-device X.509 certificate; mutual TLS. AWS authenticates the device and the device authenticates AWS |
| A stolen device reading other units' data | IoT policy permits `Connect` only under the device's own client id and `Publish` only to its own topic; no `Subscribe` at all |
| Forged device identity in the payload | The device id comes from the MQTT topic (`topic(3)` in the rule), which the policy constrains — not from a field the device can edit |
| Malformed or forged readings (Tampering) | The ingest Lambda validates every payload: type, presence, and physical plausibility. Rejects are logged and alarmed, never stored |
| Compromised device | Its certificate is revoked individually; no shared secret to rotate across a fleet |
| Telemetry loss going unnoticed | The read API reports `stale` when the newest reading is over 15 minutes old |

The device zone is treated as **untrusted**. IoT Core proves the device holds a
valid certificate; it says nothing about whether the payload is sensible, so
the ingest function validates input exactly as the patient API does.

## Deploy

```bash
cd iot
sam build
sam deploy --guided --stack-name securehealth-iot
# Parameters: DeviceName securehealth-fridge-01, MinSafeC 2, MaxSafeC 8,
#             UserPoolId <from the main stack outputs>
```

Then provision the device certificate (once):

```bash
./provision.sh
```

This writes `certs/` and prints the data endpoint. **`certs/` is gitignored** —
AWS returns the private key exactly once and it must never be committed.

Subscribe to equipment alerts:

```bash
aws sns subscribe --topic-arn <AlertTopicArn> --protocol email \
  --notification-endpoint you@example.com --region ca-central-1
```

## Run without hardware

```bash
pip install paho-mqtt
python simulate_device.py --endpoint <data-endpoint> --scenario normal
```

Scenarios:

- `normal` — steady readings in range
- `excursion` — temperature drifts out of range, triggering the alarm and email
- `spoof` — a malformed payload, showing validation reject it

## Run on hardware

1. Wire per the header comment in `firmware/securehealth_monitor.ino`
   (DHT11 → GPIO 4; OLED SDA → GPIO 21, SCL → GPIO 22).
2. `cp firmware/secrets.h.example firmware/secrets.h` and paste in the Wi-Fi
   credentials, endpoint, and the three certificate files from `certs/`.
3. Install the libraries listed in the firmware header, select **ESP32 Dev
   Module**, and flash.
4. The OLED shows the live reading; the serial monitor at 115200 shows each
   publish.

## Verify

```bash
# Watch messages arrive at IoT Core (console)
#   AWS IoT → Test → MQTT test client → subscribe to securehealth/telemetry/#

# Stored readings
aws dynamodb query --table-name securehealth-telemetry \
  --key-condition-expression "device_id = :d" \
  --expression-attribute-values '{":d":{"S":"securehealth-fridge-01"}}' \
  --region ca-central-1 --max-items 5

# Through the authenticated API
curl.exe -s "<TelemetryApiUrl>?limit=10" -H "Authorization: Bearer $SECUREHEALTH_ADMIN_TOKEN"
```

## Demo sequence

1. Start the simulator (or power the ESP32) — readings appear in the MQTT test
   client and in DynamoDB.
2. Switch to `--scenario excursion` — temperature climbs past 8 °C, the
   `SecureHealth-EquipmentOutOfRange` alarm fires, and an email arrives.
3. Switch to `--scenario spoof` — the payload is rejected, logged as
   `TELEMETRY_REJECTED`, and never stored.
4. Show the IoT policy: this certificate can publish to one topic and subscribe
   to nothing.

## Teardown

```bash
aws cloudformation delete-stack --stack-name securehealth-iot --region ca-central-1
```

Detach and delete the certificate first, or the thing will refuse to delete.
