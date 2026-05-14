/**
 * ============================================================
 *  AIRBORNE RELAY — ESP32-S3 Arduino Sketch
 *  Search & Rescue Proof of Concept
 * ============================================================
 *  Mode    : AP + STA (simultaneous)
 *  AP SSID : RESCUE_NODE  (open, no password)
 *  STA     : Connects upstream to command network
 *  NAT     : Routes victim traffic via ESP32 NAT
 *  Sniffer : Promiscuous mode probe-request harvester
 *  Report  : UDP packet to command server every 5 seconds
 * ============================================================
 *
 *  Board: "ESP32S3 Dev Module"
 *  Arduino ESP32 board package v2.x+
 * ============================================================
 */

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiAP.h>
#include <WiFiUdp.h>
#include <esp_wifi.h>
#include "esp_netif.h"
#include "lwip/ip_addr.h"

// Try to include NAPT header — available on some ESP32 builds
// If compilation fails here, NAPT will be disabled (sniffer still works)
#if __has_include("lwip/lwip_napt.h")
  #include "lwip/lwip_napt.h"
  #define NAPT_AVAILABLE 1
#elif __has_include("esp_netif_napt.h")
  #include "esp_netif_napt.h"
  #define NAPT_AVAILABLE 2
#else
  #define NAPT_AVAILABLE 0
#endif

// ─── CONFIG ──────────────────────────────────────────────────
// Upstream network (STA side) — the network your Pi/VM is on
const char* STA_SSID     = "reda";             // Your Wi-Fi SSID
const char* STA_PASSWORD = "";                 // Empty = open network

// Victim-facing AP
const char* AP_SSID      = "RESCUE_NODE";      // Open AP — no password

// Command Server address — your VM's IP
const char* PI_IP        = "172.16.166.245";   // VM IP
const uint16_t UDP_PORT  = 5005;               // UDP port server listens on

// Sniffer report interval
const unsigned long REPORT_INTERVAL_MS = 5000;

// ─── GLOBALS ─────────────────────────────────────────────────
WiFiUDP udp;

struct ProbeEntry {
  char mac[18];
  int8_t rssi;
  unsigned long ts;
};

// Ring buffer for captured probe entries
static const int PROBE_BUF_SIZE = 64;
static ProbeEntry probeBuf[PROBE_BUF_SIZE];
static volatile int probeBufHead = 0;
static int probeBufTail = 0;
static portMUX_TYPE probeMux = portMUX_INITIALIZER_UNLOCKED;

unsigned long lastReportMs = 0;

// ─── PROMISCUOUS SNIFFER CALLBACK ────────────────────────────
/**
 * Wi-Fi promiscuous callback. Called for EVERY frame seen on-air.
 * We filter for Management frames (type=0) Probe Requests (subtype=4).
 *
 * 802.11 frame layout:
 *   Byte 0    : Frame Control byte 0 -> [7:4]=subtype [3:2]=type
 *   Bytes 10-15: Source MAC (victim device MAC)
 *
 * The esp32 SDK gives us wifi_promiscuous_pkt_t which prepends RSSI.
 */
void snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;

  const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* payload = pkt->payload;
  int8_t rssi = pkt->rx_ctrl.rssi;

  // Frame Control byte 0: bits [7:4]=subtype, bits [3:2]=type
  uint8_t fc0 = payload[0];
  uint8_t frame_type    = (fc0 >> 2) & 0x03;  // Management = 0x00
  uint8_t frame_subtype = (fc0 >> 4) & 0x0F;  // Probe Request = 0x04

  if (frame_type != 0x00 || frame_subtype != 0x04) return;

  // Source MAC is at bytes 10..15
  if (pkt->rx_ctrl.sig_len < 16) return;
  const uint8_t* mac = payload + 10;

  portENTER_CRITICAL_ISR(&probeMux);
  int nextHead = (probeBufHead + 1) % PROBE_BUF_SIZE;
  if (nextHead != probeBufTail) {  // not full
    ProbeEntry& e = probeBuf[probeBufHead];
    snprintf(e.mac, sizeof(e.mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    e.rssi = rssi;
    e.ts = millis();
    probeBufHead = nextHead;
  }
  portEXIT_CRITICAL_ISR(&probeMux);
}

// ─── HELPERS ─────────────────────────────────────────────────
/**
 * Try to enable NAPT if available on this build.
 * If not available, the ESP32 still works as a sniffer + AP,
 * just without automatic NAT routing.
 */
void enableNAPT() {
#if NAPT_AVAILABLE == 1
  // Old-style lwip NAPT
  ip_napt_enable_no(1, 1);  // netif index 1 = AP interface
  Serial.println("[NAT] NAPT enabled (lwip method)");
#elif NAPT_AVAILABLE == 2
  // New esp-idf style NAPT
  esp_netif_t* ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  if (ap_netif) {
    esp_netif_napt_enable(ap_netif);
    Serial.println("[NAT] NAPT enabled (esp_netif method)");
  } else {
    Serial.println("[NAT] WARNING: Could not get AP netif handle");
  }
#else
  Serial.println("[NAT] NAPT not available on this build - sniffer-only mode");
  Serial.println("[NAT] Victims can connect to AP but traffic won't route automatically");
  Serial.println("[NAT] This is OK for the probe-sniffer demo!");
#endif
}

/**
 * Send probe report via UDP.
 * Format: MAC|RSSI\nMAC|RSSI\n...
 */
void sendProbeReport() {
  String payload = "";
  int count = 0;

  portENTER_CRITICAL(&probeMux);
  while (probeBufTail != probeBufHead && count < 20) {
    ProbeEntry& e = probeBuf[probeBufTail];
    payload += String(e.mac) + "|" + String(e.rssi) + "\n";
    probeBufTail = (probeBufTail + 1) % PROBE_BUF_SIZE;
    count++;
  }
  portEXIT_CRITICAL(&probeMux);

  if (count == 0) return;

  Serial.printf("[SNIFFER] Sending %d probe entries to server\n", count);

  udp.beginPacket(PI_IP, UDP_PORT);
  udp.print(payload);
  udp.endPacket();
}

// ─── SETUP ───────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  delay(1000);  // Give S3 time to initialize USB-CDC
  Serial.println("\n\n=== AIRBORNE RELAY BOOT (ESP32-S3) ===");

  // ── 1. Set Wi-Fi to AP+STA mode ──────────────────────────
  WiFi.mode(WIFI_AP_STA);
  delay(100);

  // ── 2. Configure and start the victim-facing AP ──────────
  IPAddress apLocalIP(192, 168, 4, 1);
  IPAddress apGateway(192, 168, 4, 1);
  IPAddress apSubnet(255, 255, 255, 0);

  WiFi.softAPConfig(apLocalIP, apGateway, apSubnet);
  WiFi.softAP(AP_SSID);   // Open AP — no password
  Serial.printf("[AP] SSID='%s' IP=%s\n", AP_SSID, WiFi.softAPIP().toString().c_str());

  // ── 3. Connect STA to upstream network ────────────────────
  Serial.printf("[STA] Connecting to '%s'...\n", STA_SSID);
  if (strlen(STA_PASSWORD) > 0) {
    WiFi.begin(STA_SSID, STA_PASSWORD);
  } else {
    WiFi.begin(STA_SSID);  // Open network — no password
  }

  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 30) {
    delay(500);
    Serial.print(".");
    tries++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("\n[STA] Connected! IP=%s\n", WiFi.localIP().toString().c_str());
  } else {
    Serial.println("\n[STA] WARNING: Could not connect. Sniffer-only mode.");
  }

  // ── 4. Enable NAPT (if available) ────────────────────────
  enableNAPT();

  // ── 5. Start UDP socket ───────────────────────────────────
  udp.begin(UDP_PORT);
  Serial.printf("[UDP] Socket open on port %d\n", UDP_PORT);

  // ── 6. Enable Wi-Fi Promiscuous Sniffer ──────────────────
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
  Serial.println("[SNIFFER] Promiscuous mode enabled. Capturing probe requests.");

  Serial.println("=== AIRBORNE RELAY READY ===\n");
}

// ─── LOOP ────────────────────────────────────────────────────
void loop() {
  unsigned long now = millis();

  if (now - lastReportMs >= REPORT_INTERVAL_MS) {
    lastReportMs = now;

    if (WiFi.status() == WL_CONNECTED) {
      sendProbeReport();
    } else {
      Serial.println("[WARN] STA disconnected. Attempting reconnect...");
      WiFi.reconnect();
    }
  }

  // Yield to system tasks
  delay(10);
}
