#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClient.h>
#include <ArduinoJson.h>

// Configuration - UPDATE THESE VALUES
const char* WIFI_SSID = "Sunil BSNL";  // Your WiFi network name
const char* WIFI_PASSWORD = "9844007710";  // Your WiFi password

const char* SERVER_URL = "http://192.168.1.37:5000/api/scan";  // Change for production
const char* API_KEY = "wifi-detector-secret-key-2025";  // Match your .env file
const char* DEVICE_ID = "ESP8266_001";

// Timing configuration
const unsigned long SCAN_INTERVAL = 30000;  // 30 seconds between scans
const unsigned long WIFI_TIMEOUT = 10000;   // 10 seconds WiFi connection timeout
const unsigned long HTTP_TIMEOUT = 15000;   // 15 seconds HTTP timeout

// Global variables
WiFiClient wifiClient;
HTTPClient http;
unsigned long lastScanTime = 0;
int scanCount = 0;

void setup() {
  Serial.begin(115200);
  delay(1000);
  
  Serial.println("\n================================================");
  Serial.println("WiFi Intrusion Detector ESP8266");
  Serial.println("Device ID: " + String(DEVICE_ID));
  Serial.println("================================================");
  
  // Initialize WiFi
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  
  connectToWiFi();
  
  Serial.println("Setup completed. Starting network scanning...\n");
}

void loop() {
  unsigned long currentTime = millis();
  
  // Check WiFi connection
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("⚠️  WiFi connection lost. Reconnecting...");
    connectToWiFi();
  }
  
  // Perform scan at specified interval
  if (currentTime - lastScanTime >= SCAN_INTERVAL) {
    performNetworkScan();
    lastScanTime = currentTime;
  }
  
  delay(1000);  // Small delay to prevent overwhelming the CPU
}

void connectToWiFi() {
  Serial.print("🔗 Connecting to WiFi: " + String(WIFI_SSID));
  
  // First scan to find the network and its encryption type
  String encryptionTypeStr = "Unknown";
  int networkCount = WiFi.scanNetworks();
  
  for (int i = 0; i < networkCount; i++) {
    if (WiFi.SSID(i) == String(WIFI_SSID)) {
      encryptionTypeStr = getEncryptionType(WiFi.encryptionType(i));
      break;
    }
  }
  
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  
  unsigned long startTime = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - startTime < WIFI_TIMEOUT) {
    delay(500);
    Serial.print(".");
  }
  
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println(" ✅");
    Serial.println("📡 WiFi connected successfully!");
    Serial.println("🌐 IP Address: " + WiFi.localIP().toString());
    Serial.println("📶 Signal Strength: " + String(WiFi.RSSI()) + " dBm");
    Serial.println("🔐 Encryption: " + encryptionTypeStr);
  } else {
    Serial.println(" ❌");
    Serial.println("Failed to connect to WiFi. Retrying in 10 seconds...");
    delay(10000);
    connectToWiFi();
  }
}


void performNetworkScan() {
  scanCount++;
  Serial.println("📡 Starting network scan #" + String(scanCount) + "...");
  
  int networkCount = WiFi.scanNetworks();
  
  if (networkCount == 0) {
    Serial.println("No networks found");
    return;
  }
  
  Serial.println("Found " + String(networkCount) + " networks:");
  
  // Create JSON payload
  DynamicJsonDocument jsonDoc(8192);  // 8KB buffer
  jsonDoc["deviceId"] = DEVICE_ID;
  JsonArray networks = jsonDoc.createNestedArray("networks");
  
  // Process each network
  for (int i = 0; i < networkCount; i++) {
    String ssid = WiFi.SSID(i);
    String bssid = WiFi.BSSIDstr(i);
    int32_t rssi = WiFi.RSSI(i);
    uint8_t channel = WiFi.channel(i);
    String encType = getEncryptionType(WiFi.encryptionType(i));
    
    // Create network object
    JsonObject network = networks.createNestedObject();
    network["ssid"] = ssid.length() > 0 ? ssid : "Hidden Network";
    network["bssid"] = bssid;
    network["rssi"] = rssi;
    network["channel"] = channel;
    network["encType"] = encType;
    
    // Print to serial
    Serial.printf("  %2d: %-20s %s (Ch:%2d, %4ddBm, %s)\n", 
                  i + 1, 
                  ssid.c_str(),
                  bssid.c_str(),
                  channel,
                  rssi,
                  encType.c_str());
  }
  
  // Send data to server
  String jsonString;
  serializeJson(jsonDoc, jsonString);
  
  bool success = sendToServer(jsonString);
  
  if (success) {
    Serial.println("✅ Successfully sent " + String(networkCount) + " networks to server");
  } else {
    Serial.println("❌ Failed to send data to server");
  }
  
  Serial.println("⏱️  Next scan in " + String(SCAN_INTERVAL / 1000) + " seconds\n");
  
  // Cleanup
  WiFi.scanDelete();
}

bool sendToServer(String jsonPayload) {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("❌ Not connected to WiFi");
    return false;
  }
  
  http.begin(wifiClient, SERVER_URL);
  http.setTimeout(HTTP_TIMEOUT);
  http.addHeader("Content-Type", "application/json");
  http.addHeader("x-api-key", API_KEY);
  
  Serial.println("📤 Sending data to server...");
  
  int httpResponseCode = http.POST(jsonPayload);
  
  if (httpResponseCode > 0) {
    String response = http.getString();
    Serial.println("📥 Server response (" + String(httpResponseCode) + "): " + response);
    
    http.end();
    return httpResponseCode >= 200 && httpResponseCode < 300;
  } else {
    Serial.println("❌ HTTP Error: " + String(httpResponseCode));
    Serial.println("Error: " + http.errorToString(httpResponseCode));
    
    http.end();
    return false;
  }
}

String getEncryptionType(uint8_t encryptionType) {
  switch (encryptionType) {
    case ENC_TYPE_WEP:
      return "WEP";
    case ENC_TYPE_TKIP:
      return "WPA";
    case ENC_TYPE_CCMP:
      return "WPA2";
    case ENC_TYPE_AUTO:
      return "WPA/WPA2";
    case ENC_TYPE_NONE:
      return "Open";
    default:
      return "Unknown";
  }
}
