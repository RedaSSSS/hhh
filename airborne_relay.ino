/**
 * ============================================================
 *  AIRBORNE RELAY — ESP32-S3 (Full Version)
 *  Search & Rescue Proof of Concept
 * ============================================================
 *  Board: "ESP32S3 Dev Module"
 *  Flash Size: 8MB, Flash Mode: QIO 80MHz, PSRAM: Disabled
 * ============================================================
 */

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiAP.h>
#include <WiFiUdp.h>
#include <esp_wifi.h>

// ─── CONFIG ──────────────────────────────────────────────────
const char* STA_SSID     = "reda";
const char* AP_SSID      = "RESCUE_NODE";
const char* PI_IP        = "192.168.1.116";
const uint16_t UDP_PORT  = 5005;
const unsigned long REPORT_INTERVAL_MS = 5000;

// ─── GLOBALS ─────────────────────────────────────────────────
WiFiUDP udp;

struct ProbeEntry {
  char mac[18];
  int8_t rssi;
};

static const int PROBE_BUF_SIZE = 32;
static ProbeEntry probeBuf[PROBE_BUF_SIZE];
static volatile int probeCount = 0;
static portMUX_TYPE probeMux = portMUX_INITIALIZER_UNLOCKED;

unsigned long lastReportMs = 0;

// ─── SNIFFER CALLBACK ────────────────────────────────────────
void snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;

  const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* payload = pkt->payload;

  uint8_t fc0 = payload[0];
  uint8_t frame_type    = (fc0 >> 2) & 0x03;
  uint8_t frame_subtype = (fc0 >> 4) & 0x0F;

  if (frame_type != 0x00 || frame_subtype != 0x04) return;
  if (pkt->rx_ctrl.sig_len < 16) return;

  const uint8_t* mac = payload + 10;
  int8_t rssi = pkt->rx_ctrl.rssi;

  portENTER_CRITICAL_ISR(&probeMux);
  if (probeCount < PROBE_BUF_SIZE) {
    snprintf(probeBuf[probeCount].mac, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    probeBuf[probeCount].rssi = rssi;
    probeCount++;
  }
  portEXIT_CRITICAL_ISR(&probeMux);
}

// ─── SETUP ───────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  delay(3000);
  Serial.println();
  Serial.println("=== AIRBORNE RELAY BOOT (S3) ===");

  // Step 1: Connect to Wi-Fi
  Serial.printf("[STA] Connecting to '%s'...\n", STA_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(STA_SSID);

  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 20) {
    delay(1000);
    Serial.print(".");
    tries++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("\n[STA] Connected! IP=%s\n", WiFi.localIP().toString().c_str());
  } else {
    Serial.println("\n[STA] WARNING: Not connected. Will work in sniffer-only mode.");
  }

  // Step 2: Start AP
  delay(500);
  WiFi.mode(WIFI_AP_STA);
  delay(500);

  if (WiFi.status() != WL_CONNECTED) {
    WiFi.begin(STA_SSID);
    delay(3000);
  }

  WiFi.softAP(AP_SSID);
  Serial.printf("[AP] SSID='%s' IP=%s\n", AP_SSID, WiFi.softAPIP().toString().c_str());

  // Step 3: Start UDP
  udp.begin(UDP_PORT);
  Serial.printf("[UDP] Ready on port %d\n", UDP_PORT);

  // Step 4: Start sniffer
  delay(1000);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
  Serial.println("[SNIFFER] Active - capturing probe requests");

  Serial.println("=== AIRBORNE RELAY READY ===");
}

// ─── LOOP ────────────────────────────────────────────────────
void loop() {
  unsigned long now = millis();

  if (now - lastReportMs >= REPORT_INTERVAL_MS) {
    lastReportMs = now;

    // Pause sniffer while sending
    esp_wifi_set_promiscuous(false);

    // Copy buffer
    int count = 0;
    ProbeEntry localBuf[PROBE_BUF_SIZE];

    portENTER_CRITICAL(&probeMux);
    count = probeCount;
    if (count > 0) {
      memcpy(localBuf, probeBuf, sizeof(ProbeEntry) * count);
      probeCount = 0;
    }
    portEXIT_CRITICAL(&probeMux);

    if (count > 0 && WiFi.status() == WL_CONNECTED) {
      String payload = "";
      for (int i = 0; i < count; i++) {
        payload += String(localBuf[i].mac) + "|" + String(localBuf[i].rssi) + "\n";
      }
      udp.beginPacket(PI_IP, UDP_PORT);
      udp.print(payload);
      udp.endPacket();
      Serial.printf("[SENT] %d probes to server\n", count);
    } else if (count > 0) {
      Serial.printf("[LOCAL] %d probes (no connection)\n", count);
      for (int i = 0; i < count && i < 5; i++) {
        Serial.printf("  %s | %d dBm\n", localBuf[i].mac, localBuf[i].rssi);
      }
    }

    if (WiFi.status() != WL_CONNECTED) {
      Serial.println("[STA] Reconnecting...");
      WiFi.reconnect();
    }

    // Resume sniffer
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
  }

  delay(100);
}
