/*
 * SecureHealth equipment monitor - ESP32 firmware
 *
 * Reads a DHT11 temperature/humidity sensor, shows the current value on a
 * 0.96" SSD1306 OLED, and publishes to AWS IoT Core over MQTT protected by
 * mutual TLS. The device holds its own X.509 certificate; the certificate is
 * what identifies it, so a stolen unit can be revoked individually without
 * touching any other device.
 *
 * Board:    ESP32 Dev Module (ESP32-WROOM-32)
 * Wiring:   DHT11 data -> GPIO 4      OLED SDA -> GPIO 21
 *           DHT11 VCC  -> 3V3         OLED SCL -> GPIO 22
 *           DHT11 GND  -> GND         OLED VCC -> 3V3, GND -> GND
 *
 * Libraries (Library Manager):
 *   DHT sensor library, Adafruit Unified Sensor,
 *   Adafruit SSD1306, Adafruit GFX, PubSubClient, ArduinoJson
 *
 * secrets.h holds the Wi-Fi credentials and the three certificate strings.
 * It is gitignored and never committed.
 */

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <DHT.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#include "secrets.h"   // WIFI_SSID, WIFI_PASSWORD, AWS_IOT_ENDPOINT,
                       // AWS_CERT_CA, AWS_CERT_CRT, AWS_CERT_PRIVATE

#define DEVICE_NAME  "securehealth-fridge-01"
#define MQTT_TOPIC   "securehealth/telemetry/" DEVICE_NAME

#define DHT_PIN      4
#define DHT_TYPE     DHT11
#define SCREEN_W     128
#define SCREEN_H     64
#define OLED_ADDR    0x3C

// Safe storage range for vaccine refrigeration, matching the cloud thresholds.
const float MIN_SAFE_C = 2.0;
const float MAX_SAFE_C = 8.0;

const unsigned long PUBLISH_INTERVAL_MS = 30000;  // one reading every 30 s

DHT dht(DHT_PIN, DHT_TYPE);
Adafruit_SSD1306 display(SCREEN_W, SCREEN_H, &Wire, -1);
WiFiClientSecure net;
PubSubClient mqtt(net);

unsigned long lastPublish = 0;

void showStatus(const char *line1, const char *line2) {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println(line1);
  if (line2) {
    display.setCursor(0, 12);
    display.println(line2);
  }
  display.display();
}

void showReading(float tempC, float humidity, bool inRange, bool connected) {
  display.clearDisplay();

  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println(F("SecureHealth Monitor"));

  display.setTextSize(3);
  display.setCursor(0, 18);
  display.print(tempC, 1);
  display.println(F("C"));

  display.setTextSize(1);
  display.setCursor(0, 46);
  display.print(F("RH "));
  display.print(humidity, 0);
  display.println(F("%"));

  display.setCursor(0, 56);
  if (!inRange) {
    display.print(F("** OUT OF RANGE **"));
  } else {
    display.print(connected ? F("OK  cloud: linked") : F("OK  cloud: offline"));
  }
  display.display();
}

void connectWiFi() {
  showStatus("Connecting to WiFi", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print('.');
  }
  Serial.println("\nWiFi connected");
}

void connectAWS() {
  // Load the three credentials that make this a mutually authenticated
  // connection: the Amazon root CA authenticates AWS to the device, and the
  // device certificate and private key authenticate the device to AWS.
  net.setCACert(AWS_CERT_CA);
  net.setCertificate(AWS_CERT_CRT);
  net.setPrivateKey(AWS_CERT_PRIVATE);

  mqtt.setServer(AWS_IOT_ENDPOINT, 8883);

  showStatus("Connecting to AWS", "IoT Core (mTLS)");
  Serial.print("Connecting to AWS IoT Core");

  // The client id must match the device name: the IoT policy authorises this
  // certificate to connect only under its own identity.
  while (!mqtt.connect(DEVICE_NAME)) {
    Serial.print('.');
    delay(2000);
  }
  Serial.println("\nConnected to AWS IoT Core");
}

void setup() {
  Serial.begin(115200);
  delay(500);

  Wire.begin();
  if (!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR)) {
    Serial.println("OLED not found - check I2C wiring");
  }
  display.clearDisplay();
  display.display();

  dht.begin();
  connectWiFi();
  connectAWS();
}

void publishReading(float tempC, float humidity) {
  StaticJsonDocument<192> doc;
  doc["temperature_c"] = round(tempC * 10) / 10.0;
  doc["humidity_pct"]  = round(humidity * 10) / 10.0;
  doc["firmware"]      = "esp32-1.0";

  char payload[192];
  serializeJson(doc, payload);

  // Publishing to any other topic would be refused by the IoT policy, so a
  // compromised device cannot reach another unit's data.
  if (mqtt.publish(MQTT_TOPIC, payload)) {
    Serial.print("Published: ");
    Serial.println(payload);
  } else {
    Serial.println("Publish failed");
  }
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) connectWiFi();
  if (!mqtt.connected()) connectAWS();
  mqtt.loop();

  if (millis() - lastPublish < PUBLISH_INTERVAL_MS) return;
  lastPublish = millis();

  float tempC    = dht.readTemperature();
  float humidity = dht.readHumidity();

  // A failed read returns NaN. Sending it would be a malformed payload, so the
  // device drops it rather than letting the cloud reject it.
  if (isnan(tempC) || isnan(humidity)) {
    Serial.println("Sensor read failed - skipping this interval");
    showStatus("Sensor read failed", "retrying");
    return;
  }

  bool inRange = (tempC >= MIN_SAFE_C && tempC <= MAX_SAFE_C);
  showReading(tempC, humidity, inRange, mqtt.connected());
  publishReading(tempC, humidity);
}
