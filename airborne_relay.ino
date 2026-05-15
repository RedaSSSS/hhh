/**
 * AIRBORNE RELAY — ESP32-S3 (Ultra-Minimal Test)
 * Just connects to Wi-Fi and prints. Nothing else.
 * If this boot-loops, the problem is hardware/board-config, not code.
 */

#include <Arduino.h>
#include <WiFi.h>

const char* STA_SSID = "reda";

void setup() {
  Serial.begin(115200);
  delay(3000);
  Serial.println();
  Serial.println("=== BOOT OK ===");

  WiFi.mode(WIFI_STA);
  WiFi.begin(STA_SSID);

  Serial.print("Connecting to WiFi");
  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 20) {
    delay(1000);
    Serial.print(".");
    tries++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println();
    Serial.print("Connected! IP: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println();
    Serial.println("Failed to connect");
  }
}

void loop() {
  delay(5000);
  Serial.println("alive");
}
