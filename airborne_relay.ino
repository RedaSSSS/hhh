/**
 * ============================================================
 *  AIRBORNE RELAY — ESP32 Arduino Sketch
 *  Search & Rescue Proof of Concept
 * ============================================================
 *  Mode    : AP + STA (simultaneous)
 *  AP SSID : RESCUE_NODE  (open, no password)
 *  STA     : Connects upstream to Pi 3 hotspot
 *  NAT     : Routes victim traffic → Pi 3 IP
 *  Sniffer : Promiscuous mode probe-request harvester
 *  Report  : UDP packet to Pi 3 every 5 seconds
 * ============================================================
 *
 *  Required libraries (install via Arduino Library Manager):
 *    - arduino-esp32 (Espressif) v2.x+
 *    - lwip_napt patch (included in esp32 arduino >=2.0.2)
 *
 *  Board: "ESP32 Dev Module"
 * ============================================================
 */

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiAP.h>
#include <WiFiUdp.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <lwip/lwip_napt.h>   // NAT/NAPT support
#include <lwip/ip4_addr.h>

// ─── CONFIG ──────────────────────────────────────────────────
// Upstream network: the Pi 3 hotspot (STA side)
const char* STA_SSID     = "PI_COMMAND_NET";   // Pi 3 hotspot SSID
const char* STA_PASSWORD = "rescue2024";       // Pi 3 hotspot password

// Victim-facing AP
const char* AP_SSID      = "RESCUE_NODE";      // Open AP — no password
const char* AP_IP        = "192.168.4.1";      // ESP32 AP gateway IP
const char* AP_GATEWAY   = "192.168.4.1";
const char* AP_SUBNET    = "255.255.255.0";

// Command Server (Pi 3) address — on the STA subnet
const char* PI_IP        = "10.0.0.1";         // Pi 3 IP on its own hotspot
const uint16_t UDP_PORT  = 5005;               // UDP port Pi 3 listens on

// Sniffer report interval
const unsigned long REPORT_INTERVAL_MS = 5000;

// ─── GLOBALS ─────────────────────────────────────────────────
WiFiUDP udp;

struct ProbeEntry {
  char mac[18];
  int8_t rssi;
  unsigned long ts;  // millis() when seen
};

// Ring buffer for captured probe entries
static const int PROBE_BUF_SIZE = 64;
static ProbeEntry probeBuf[PROBE_BUF_SIZE];
static volatile int probeBufHead = 0;  // written by sniffer ISR-like callback
static int probeBufTail = 0;           // read by main task
static portMUX_TYPE probeMux = portMUX_INITIALIZER_UNLOCKED;

unsigned long lastReportMs = 0;

// ─── PROMISCUOUS SNIFFER CALLBACK ────────────────────────────
/**
 * Wi-Fi promiscuous callback. Called for EVERY frame seen on-air.
 * We filter for Management frames (type=0) Probe Requests (subtype=4).
 *
 * 802.11 frame layout (simplified):
 *   Byte 0    : Frame Control byte 0  → [7:4]=subtype [3:2]=type [1:0]=protocol
 *   Byte 1    : Frame Control byte 1
 *   Bytes 4-9 : Destination MAC
 *   Bytes 10-15: Source MAC          ← victim device MAC
 *   ...
 *
 * The esp32 SDK gives us wifi_promiscuous_pkt_t which prepends RSSI.
 */
typedef struct {
  uint8_t  frame_ctrl[2];
  uint16_t duration;
  uint8_t  dest[6];
  uint8_t  src[6];    // ← Source MAC address
  uint8_t  bssid[6];
  uint16_t seq_ctrl;
  // SSID element follows (variable)
} ieee80211_mgmt_hdr_t;

void IRAM_ATTR snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
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
 * Enable NAPT (Network Address Port Translation) on the AP interface.
 * This makes the ESP32 a NAT router: victims on 192.168.4.x get their
 * packets masqueraded and forwarded through the STA interface to Pi 3.
 */
void enableNAPT() {
  ip4_addr_t apIP, apGW, apNM;
  IP4_ADDR(&apIP, 192, 168, 4, 1);
  IP4_ADDR(&apGW, 192, 168, 4, 1);
  IP4_ADDR(&apNM, 255, 255, 255, 0);

  // Index 0 = STA (upstream), Index 1 = AP (downstream)
  // Enable forwarding globally
  ip_napt_enable(apIP.addr, 1);

  Serial.println("[NAT] NAPT enabled on AP interface (192.168.4.1)");
}

/**
 * Build a compact JSON-like UDP payload from the probe ring buffer.
 * Format: MAC|RSSI\nMAC|RSSI\n...
 * Kept lightweight — Pi 3 parses it line by line.
 */
void sendProbeReport() {
  // Drain the ring buffer into a local snapshot
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

  if (count == 0) return;  // Nothing to report

  Serial.printf("[SNIFFER] Sending %d probe entries to Pi 3\n", count);

  udp.beginPacket(PI_IP, UDP_PORT);
  udp.print(payload);
  udp.endPacket();
}

// ─── SETUP ───────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("\n\n=== AIRBORNE RELAY BOOT ===");

  // ── 1. Set Wi-Fi to AP+STA mode ──────────────────────────
  WiFi.mode(WIFI_AP_STA);

  // ── 2. Configure and start the victim-facing AP ──────────
  IPAddress apLocalIP(192, 168, 4, 1);
  IPAddress apGateway(192, 168, 4, 1);
  IPAddress apSubnet(255, 255, 255, 0);

  WiFi.softAPConfig(apLocalIP, apGateway, apSubnet);
  WiFi.softAP(AP_SSID);   // Open AP — no password argument
  Serial.printf("[AP] SSID='%s' IP=%s\n", AP_SSID, WiFi.softAPIP().toString().c_str());

  // ── 3. Connect STA to Pi 3 hotspot ───────────────────────
  Serial.printf("[STA] Connecting to '%s'...\n", STA_SSID);
  WiFi.begin(STA_SSID, STA_PASSWORD);

  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 30) {
    delay(500);
    Serial.print(".");
    tries++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("\n[STA] Connected! IP=%s\n", WiFi.localIP().toString().c_str());
  } else {
    Serial.println("\n[STA] WARNING: Could not connect to Pi 3. Relay in offline mode.");
  }

  // ── 4. Enable NAPT ───────────────────────────────────────
  enableNAPT();

  // ── 5. Start UDP socket ───────────────────────────────────
  udp.begin(UDP_PORT);
  Serial.printf("[UDP] Socket open on port %d\n", UDP_PORT);

  // ── 6. Enable Wi-Fi Promiscuous Sniffer ──────────────────
  //  IMPORTANT: promiscuous mode works on the current Wi-Fi channel.
  //  The ESP32 will sniff on the channel it's associated to (STA channel).
  //  For broader coverage in a real deployment, you'd hop channels,
  //  but for PoC this captures probes near the drone's operating channel.
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

  // Brief yield — sniffer callback runs in wifi driver context
  delay(10);
}
