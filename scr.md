# FIRMWARE TEAM - Security Remediation Tasks

**Project:** SensorWatch IoT Security Hardening  
**Component:** ESP32 Firmware (`src/main.cpp`)  
**Audit Date:** October 29, 2025  
**Priority:** CRITICAL - Production Blocker

---

## CRITICAL ISSUES

### C1: Hardcoded Credentials in Source Code
**CVSS Score:** 10.0 | **CWE-798**

**How Discovered:**
Source code review revealed WiFi credentials, API keys, and admin passwords embedded directly in `main.cpp` lines 104-107.

**Current Vulnerable Code:**
```cpp
String wifiSSID = "2.4";
String wifiPassword = "P1rates15";
String remoteApiKey = "tPmAT5Ab3j7F9";
```

**Security Impact:**
- Anyone with repository access can extract credentials
- Firmware binary strings expose credentials
- Credentials cannot be rotated without firmware recompilation
- Network compromise enables lateral movement

**Required Fix:**
Implement secure credential storage using ESP32 NVS (Non-Volatile Storage).

```cpp
#include <Preferences.h>

Preferences prefs;
String wifiSSID;
String wifiPassword;
String remoteApiKey;

void loadCredentials() {
    prefs.begin("credentials", true);
    wifiSSID = prefs.getString("wifi_ssid", "");
    wifiPassword = prefs.getString("wifi_pass", "");
    remoteApiKey = prefs.getString("api_key", "");
    prefs.end();
}

void setup() {
    loadCredentials();
    // Continue with setup...
}
```

**Provisioning Mechanism Needed:**
Create secure provisioning interface (BLE or temporary web portal) for initial credential setup.

**Deliverables:**
- [ ] Remove all hardcoded credentials from source
- [ ] Implement NVS-based credential storage
- [ ] Create provisioning interface
- [ ] Add credential rotation capability
- [ ] Update documentation for device setup

**Dependencies:** Security team (encryption keys for credential storage)

---

### C2: No Authentication on Web Server
**CVSS Score:** 9.1 | **CWE-306**

**How Discovered:**
Direct HTTP requests to any endpoint (tested all 27 endpoints) succeeded without providing credentials. Example:
```bash
curl http://192.168.1.100:82/serverIndex
# Returns OTA upload page with no authentication
```

**Affected Endpoints:**
All HTTP endpoints lack authentication middleware:
- `/` - Dashboard
- `/serverIndex` - OTA firmware upload
- `/update` - Firmware upload handler
- `/manage` - Management panel
- `/fs` - File system manager
- `/download` - File download
- `/upload-file` - File upload
- `/delete-file` - File deletion
- `/format-fs` - Format filesystem
- `/connectivity` - WiFi configuration
- `/restart` - Device reboot
- 16+ additional endpoints

**Security Impact:**
- Anyone on network has full administrative access
- Firmware can be replaced with malicious code
- Configuration files can be stolen or modified
- Device can be bricked or hijacked

**Required Fix:**
Implement session-based authentication with secure token generation.

```cpp
#include <map>
#include <mbedtls/sha256.h>

std::map<String, unsigned long> activeSessions;
const unsigned long SESSION_TIMEOUT_MS = 3600000; // 1 hour

String generateSecureToken() {
    uint8_t randomBytes[32];
    esp_fill_random(randomBytes, 32);
    
    char token[65];
    for (int i = 0; i < 32; i++) {
        sprintf(token + (i * 2), "%02x", randomBytes[i]);
    }
    return String(token);
}

bool requireAuth(WebServer &server) {
    String cookie = server.header("Cookie");
    int sessionPos = cookie.indexOf("session=");
    
    if (sessionPos < 0) {
        server.sendHeader("Location", "/login");
        server.send(303);
        return false;
    }
    
    String token = cookie.substring(sessionPos + 8);
    int endPos = token.indexOf(';');
    if (endPos > 0) token = token.substring(0, endPos);
    
    if (activeSessions.find(token) == activeSessions.end()) {
        server.sendHeader("Location", "/login");
        server.send(303);
        return false;
    }
    
    unsigned long sessionTime = activeSessions[token];
    if (millis() - sessionTime > SESSION_TIMEOUT_MS) {
        activeSessions.erase(token);
        server.sendHeader("Location", "/login");
        server.send(303);
        return false;
    }
    
    activeSessions[token] = millis(); // Refresh session
    return true;
}

// Apply to all sensitive endpoints
server.on("/serverIndex", HTTP_GET, []() {
    if (!requireAuth(server)) return;
    server.send(200, "text/html", otaPage);
});

server.on("/restart", HTTP_POST, []() {
    if (!requireAuth(server)) return;
    ESP.restart();
});
```

**Login Handler:**
```cpp
server.on("/login", HTTP_POST, []() {
    String username = server.arg("username");
    String password = server.arg("password");
    
    // Load hashed credentials from NVS
    prefs.begin("auth", true);
    String storedHash = prefs.getString("admin_hash", "");
    prefs.end();
    
    // Hash provided password with SHA-256
    uint8_t hash[32];
    mbedtls_sha256((const unsigned char*)password.c_str(), 
                    password.length(), hash, 0);
    
    char hashStr[65];
    for(int i = 0; i < 32; i++) {
        sprintf(hashStr + (i * 2), "%02x", hash[i]);
    }
    
    if (username == "admin" && String(hashStr) == storedHash) {
        String token = generateSecureToken();
        activeSessions[token] = millis();
        
        server.sendHeader("Set-Cookie", 
            "session=" + token + "; HttpOnly; SameSite=Strict; Path=/");
        server.send(200, "text/plain", "Login successful");
    } else {
        delay(2000); // Rate limit brute force
        server.send(401, "text/plain", "Invalid credentials");
    }
});
```

**Deliverables:**
- [ ] Implement authentication middleware
- [ ] Create session management system
- [ ] Build login/logout endpoints
- [ ] Add session timeout handling
- [ ] Implement rate limiting on login
- [ ] Add CSRF token protection

**Dependencies:** Frontend team (login UI updates)

---

### C3: Cleartext HTTP Communication
**CVSS Score:** 9.0 | **CWE-319**

**How Discovered:**
Network packet capture revealed all web traffic transmitted over unencrypted HTTP on port 82, exposing:
- WiFi credentials during configuration changes
- Session tokens (once implemented)
- Sensor data
- API keys in requests

**Current Implementation:**
```cpp
WebServer server(82);  // Plain HTTP, no TLS
```

**Security Impact:**
- Man-in-the-middle attacks can intercept all traffic
- Credentials stolen during WiFi reconfiguration
- Session hijacking possible
- Data tampering in transit

**Required Fix:**
Enable HTTPS using ESP32's secure server capabilities.

```cpp
#include <WiFiClientSecure.h>
#include <WebServer.h>

// Certificate and key (load from NVS in production)
const char* serverCert = R"EOF(
-----BEGIN CERTIFICATE-----
[PEM encoded certificate]
-----END CERTIFICATE-----
)EOF";

const char* serverKey = R"EOF(
-----BEGIN RSA PRIVATE KEY-----
[PEM encoded private key]
-----END RSA PRIVATE KEY-----
)EOF";

WebServerSecure server(443);

void setup() {
    // Load certificates from secure storage
    server.setServerKeyAndCert_P(serverKey, strlen(serverKey),
                                   serverCert, strlen(serverCert));
    
    server.begin();
    Serial.println("HTTPS server started on port 443");
}
```

**Certificate Management:**
Work with Security team to obtain certificates. For development, generate self-signed:
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

**Deliverables:**
- [ ] Replace WebServer with WebServerSecure
- [ ] Implement certificate storage in NVS
- [ ] Add certificate validation
- [ ] Implement certificate renewal mechanism
- [ ] Update port from 82 to 443

**Dependencies:** Security team (certificate infrastructure)

---

### C4: Insecure Firmware Update Mechanism
**CVSS Score:** 9.3 | **CWE-494**

**How Discovered:**
Testing revealed firmware can be uploaded without authentication, signature verification, or integrity checks:
```bash
curl -X POST http://192.168.1.100:82/update -F "update=@malicious.bin"
# Firmware accepted and executed without validation
```

**Current Vulnerable Code:**
```cpp
server.on("/update", HTTP_POST, []() {
    server.send(200, "text/html", response);
}, []() {
    HTTPUpload& upload = server.upload();
    
    if (upload.status == UPLOAD_FILE_START) {
        if (!Update.begin(UPDATE_SIZE_UNKNOWN)) { // No signature check!
            Update.printError(Serial);
        }
    } 
    else if (upload.status == UPLOAD_FILE_WRITE) {
        Update.write(upload.buf, upload.currentSize); // Direct write!
    } 
    else if (upload.status == UPLOAD_FILE_END) {
        Update.end(true);
        ESP.restart(); // Executes unverified firmware!
    }
});
```

**Security Impact:**
- Attacker can install backdoored firmware
- Device can be permanently compromised
- No rollback protection allows downgrade attacks
- Enables botnet recruitment

**Required Fix:**
Implement RSA signature verification before firmware installation.

```cpp
#include <mbedtls/sha256.h>
#include <mbedtls/pk.h>

const char* FIRMWARE_PUBLIC_KEY = R"EOF(
-----BEGIN PUBLIC KEY-----
[Public key for signature verification]
-----END PUBLIC KEY-----
)EOF";

bool verifyFirmwareSignature(uint8_t* firmware, size_t size, 
                             uint8_t* signature, size_t sigLen) {
    // Calculate SHA-256 hash
    uint8_t hash[32];
    mbedtls_sha256_context sha_ctx;
    
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0);
    mbedtls_sha256_update(&sha_ctx, firmware, size);
    mbedtls_sha256_finish(&sha_ctx, hash);
    mbedtls_sha256_free(&sha_ctx);
    
    // Verify RSA signature
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    
    int ret = mbedtls_pk_parse_public_key(&pk,
                (const unsigned char*)FIRMWARE_PUBLIC_KEY,
                strlen(FIRMWARE_PUBLIC_KEY) + 1);
    
    if (ret != 0) {
        Serial.println("Failed to parse public key");
        mbedtls_pk_free(&pk);
        return false;
    }
    
    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256,
                hash, sizeof(hash), signature, sigLen);
    
    mbedtls_pk_free(&pk);
    return (ret == 0);
}

server.on("/update", HTTP_POST, []() {
    if (!requireAuth(server)) return; // Add authentication!
    
    String response = updateSuccessful ? 
        "Update successful - rebooting..." : 
        "Update failed - signature verification failed";
    
    server.send(200, "text/html", response);
}, []() {
    HTTPUpload& upload = server.upload();
    
    static uint8_t* firmwareBuffer = nullptr;
    static size_t firmwareSize = 0;
    static uint8_t signature[256];
    
    if (upload.status == UPLOAD_FILE_START) {
        // First 256 bytes are RSA signature
        if (upload.currentSize >= 256) {
            memcpy(signature, upload.buf, 256);
            firmwareBuffer = (uint8_t*)malloc(1048576);
            firmwareSize = 0;
        }
    }
    else if (upload.status == UPLOAD_FILE_WRITE) {
        if (firmwareSize + upload.currentSize <= 1048576) {
            memcpy(firmwareBuffer + firmwareSize, 
                   upload.buf, upload.currentSize);
            firmwareSize += upload.currentSize;
        }
    }
    else if (upload.status == UPLOAD_FILE_END) {
        // VERIFY SIGNATURE BEFORE FLASHING
        if (verifyFirmwareSignature(firmwareBuffer, firmwareSize, 
                                     signature, 256)) {
            Serial.println("Signature valid - updating firmware");
            
            if (Update.begin(firmwareSize)) {
                Update.write(firmwareBuffer, firmwareSize);
                
                if (Update.end(true)) {
                    updateSuccessful = true;
                    free(firmwareBuffer);
                    delay(2000);
                    ESP.restart();
                }
            }
        } else {
            Serial.println("SIGNATURE VERIFICATION FAILED");
            Update.abort();
            updateSuccessful = false;
            free(firmwareBuffer);
        }
    }
});
```

**Firmware Signing Process:**
```bash
# Generate key pair (one-time, store private key securely)
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem

# Sign firmware before distribution
openssl dgst -sha256 -binary firmware.bin > firmware.hash
openssl rsautl -sign -inkey private_key.pem -in firmware.hash -out firmware.sig

# Prepend signature to firmware
cat firmware.sig firmware.bin > signed_firmware.bin
```

**Deliverables:**
- [ ] Implement signature verification
- [ ] Add firmware version tracking
- [ ] Implement rollback protection
- [ ] Create firmware signing scripts
- [ ] Document signing process
- [ ] Integrate signing into build pipeline

**Dependencies:** Security team (key management), DevOps (CI/CD signing)

---

### C5: Unauthenticated MQTT Communication
**CVSS Score:** 9.1 | **CWE-287**

**How Discovered:**
Connected to MQTT broker without credentials:
```bash
mosquitto_sub -h 161.97.170.64 -p 1883 -t "#" -v
# Connected successfully, received all sensor data
```

**Current Implementation:**
```cpp
WiFiClient espClient;  // Plain TCP, no TLS
PubSubClient mqttClient(espClient);
mqttClient.setServer("161.97.170.64", 1883);

void ensureMqtt() {
    bool ok = mqttClient.connect(
        deviceID.c_str(),
        nullptr, nullptr,  // No authentication!
        willTopic.c_str(), 0, false, "offline"
    );
}
```

**Security Impact:**
- Anyone can subscribe to sensor data
- Attackers can inject false readings
- MQTT can be used as C2 channel for compromised devices
- All data transmitted in cleartext

**Required Fix:**
Enable MQTT over TLS with authentication.

```cpp
#include <WiFiClientSecure.h>
#include <PubSubClient.h>

// MQTT CA certificate for server verification
const char* mqtt_ca_cert = R"EOF(
-----BEGIN CERTIFICATE-----
[CA certificate for MQTT broker]
-----END CERTIFICATE-----
)EOF";

// Client certificate (optional, for mutual TLS)
const char* mqtt_client_cert = R"EOF(
-----BEGIN CERTIFICATE-----
[Client certificate]
-----END CERTIFICATE-----
)EOF";

const char* mqtt_client_key = R"EOF(
-----BEGIN RSA PRIVATE KEY-----
[Client private key]
-----END RSA PRIVATE KEY-----
)EOF";

WiFiClientSecure espClient;
PubSubClient mqttClient(espClient);

void setupMQTT() {
    // Set CA cert for server verification
    espClient.setCACert(mqtt_ca_cert);
    
    // Set client cert for mutual TLS (recommended)
    espClient.setCertificate(mqtt_client_cert);
    espClient.setPrivateKey(mqtt_client_key);
    
    // Connect to secure port
    mqttClient.setServer("161.97.170.64", 8883);
    mqttClient.setKeepAlive(20);
}

void ensureMqtt() {
    if (WiFi.status() != WL_CONNECTED) return;
    if (mqttClient.connected()) return;
    
    // Load credentials from NVS
    prefs.begin("mqtt", true);
    String mqtt_user = prefs.getString("user", "");
    String mqtt_pass = prefs.getString("pass", "");
    prefs.end();
    
    bool ok = mqttClient.connect(
        deviceID.c_str(),
        mqtt_user.c_str(),
        mqtt_pass.c_str(),
        willTopic.c_str(), 0, false, "offline"
    );
    
    if (ok) {
        Serial.println("MQTT connected securely");
    } else {
        Serial.printf("MQTT TLS connection failed: %d\n", 
                      mqttClient.state());
    }
}
```

**Deliverables:**
- [ ] Replace WiFiClient with WiFiClientSecure
- [ ] Implement certificate storage for MQTT
- [ ] Add username/password authentication
- [ ] Update to port 8883 (TLS)
- [ ] Implement certificate pinning

**Dependencies:** Backend/Infrastructure team (MQTT broker TLS configuration)

---

### C6: Insecure File System Access
**CVSS Score:** 9.1 | **CWE-22**

**How Discovered:**
Tested file operations without authentication:
```bash
# Download WiFi credentials
curl "http://192.168.1.100:82/download?file=/wifi_config.json"
# Returns: {"ssid":"2.4","password":"P1rates15"}

# Delete files
curl "http://192.168.1.100:82/delete-file?file=/labels.json"
# File deleted successfully

# Upload malicious files
curl -X POST "http://192.168.1.100:82/upload-file" -F "file=@malicious.json"
# File uploaded successfully
```

**Vulnerable Code:**
```cpp
void downloadFileHandler() {
    String filename = server.arg("file");
    if (!filename.startsWith("/")) filename = "/" + filename;
    
    // No authentication!
    // No path validation!
    // No whitelist!
    
    File downloadFile = LittleFS.open(filename, "r");
    server.streamFile(downloadFile, "application/octet-stream");
    downloadFile.close();
}
```

**Security Impact:**
- WiFi credentials can be stolen
- Configuration files can be modified
- Critical files can be deleted
- Malicious files can be uploaded

**Required Fix:**
Add authentication, path validation, and file whitelisting.

```cpp
// Whitelist of downloadable files
const char* ALLOWED_DOWNLOADS[] = {
    "/data.json",
    "/labels.json"
    // wifi_config.json intentionally excluded
};

bool isFileAllowed(String filename) {
    for (const char* allowed : ALLOWED_DOWNLOADS) {
        if (filename == allowed) return true;
    }
    return false;
}

void downloadFileHandler() {
    if (!requireAuth(server)) return; // Require authentication
    
    if (!server.hasArg("file")) {
        server.send(400, "text/plain", "Missing file parameter");
        return;
    }
    
    String filename = server.arg("file");
    if (!filename.startsWith("/")) filename = "/" + filename;
    
    // Path traversal prevention
    if (filename.indexOf("..") >= 0) {
        server.send(403, "text/plain", "Invalid filename");
        return;
    }
    
    // Whitelist check
    if (!isFileAllowed(filename)) {
        server.send(403, "text/plain", "Access denied");
        return;
    }
    
    if (!LittleFS.exists(filename)) {
        server.send(404, "text/plain", "File not found");
        return;
    }
    
    File downloadFile = LittleFS.open(filename, "r");
    server.sendHeader("Content-Disposition", 
                      "attachment; filename=\"" + 
                      filename.substring(1) + "\"");
    server.streamFile(downloadFile, "application/octet-stream");
    downloadFile.close();
}

// Secure delete handler
server.on("/delete-file", HTTP_DELETE, []() {
    if (!requireAuth(server)) return;
    
    String filename = server.arg("file");
    if (!filename.startsWith("/")) filename = "/" + filename;
    
    // Path traversal prevention
    if (filename.indexOf("..") >= 0) {
        server.send(403, "text/plain", "Invalid filename");
        return;
    }
    
    // Only allow deletion of data files
    if (filename != "/data.json" && filename != "/backfill.meta") {
        server.send(403, "text/plain", "Cannot delete system files");
        return;
    }
    
    if (LittleFS.remove(filename)) {
        server.send(200, "text/plain", "File deleted");
    } else {
        server.send(500, "text/plain", "Deletion failed");
    }
});

// Secure upload handler
void handleFileUpload() {
    if (!requireAuth(server)) return;
    
    HTTPUpload& upload = server.upload();
    
    if (upload.status == UPLOAD_FILE_START) {
        String filename = upload.filename;
        if (!filename.startsWith("/")) filename = "/" + filename;
        
        // Path traversal prevention
        if (filename.indexOf("..") >= 0) {
            server.send(403, "text/plain", "Invalid filename");
            return;
        }
        
        // Restrict upload path
        if (!filename.startsWith("/uploads/")) {
            server.send(403, "text/plain", "Invalid upload path");
            return;
        }
        
        // File size limit (1MB)
        if (upload.totalSize > 1048576) {
            server.send(413, "text/plain", "File too large");
            return;
        }
        
        fsUploadFile = LittleFS.open(filename, "w");
    }
    else if (upload.status == UPLOAD_FILE_WRITE) {
        if (fsUploadFile) {
            fsUploadFile.write(upload.buf, upload.currentSize);
        }
    }
    else if (upload.status == UPLOAD_FILE_END) {
        if (fsUploadFile) fsUploadFile.close();
    }
}
```

**Deliverables:**
- [ ] Add authentication to file endpoints
- [ ] Implement file whitelist
- [ ] Add path traversal protection
- [ ] Implement file size limits
- [ ] Add file access logging

---

## HIGH PRIORITY ISSUES

### H1: Insecure WebSocket Server
**How Discovered:** WebSocket server on port 81 accepts connections without authentication.

**Required Fix:**
```cpp
WebSocketsServer webSocket(443); // Use same port as HTTPS

void onWebSocketEvent(uint8_t num, WStype_t type, 
                      uint8_t * payload, size_t length) {
    if (type == WStype_CONNECTED) {
        // Validate session token from initial connection
        String sessionToken = (char*)payload;
        if (!validateSession(sessionToken)) {
            webSocket.disconnect(num);
            return;
        }
    }
}
```

**Deliverable:** Implement token-based WebSocket authentication

---

### H2: No Input Validation
**How Discovered:** Endpoints accept arbitrary input without validation.

**Required Fix:**
```cpp
bool validateSensorId(String id) {
    return id.length() <= 100 && 
           id.indexOf("../") < 0 &&
           id.indexOf("<") < 0;
}

bool validateTemperature(String value) {
    float temp = value.toFloat();
    return temp >= -50 && temp <= 150;
}

// Apply to all endpoints
server.on("/update-labels", HTTP_POST, []() {
    if (!requireAuth(server)) return;
    
    String sensorId = server.arg("sensor_id");
    if (!validateSensorId(sensorId)) {
        server.send(400, "text/plain", "Invalid sensor ID");
        return;
    }
    
    // Continue processing...
});
```

**Deliverable:** Input validation for all parameters

---

### H3: Insecure WiFi AP Mode
**How Discovered:** Fallback AP mode has no password (`ESP32_AP` with open access).

**Required Fix:**
```cpp
void setupAPMode() {
    // Generate random password
    uint8_t randomBytes[8];
    esp_fill_random(randomBytes, 8);
    
    char password[17];
    for(int i = 0; i < 8; i++) {
        sprintf(password + (i * 2), "%02X", randomBytes[i]);
    }
    
    WiFi.softAP("ESP32_Setup", password);
    
    // Display on serial for user
    Serial.println("======================");
    Serial.println("WiFi AP Started");
    Serial.println("SSID: ESP32_Setup");
    Serial.printf("Password: %s\n", password);
    Serial.println("======================");
}
```

**Deliverable:** Secure AP mode with random password

---

### H4: Missing Rate Limiting
**Required Fix:**
```cpp
#include <map>

struct RateLimitData {
    unsigned long lastRequest;
    int requestCount;
};

std::map<IPAddress, RateLimitData> rateLimits;

bool checkRateLimit(IPAddress ip, int maxRequests, 
                    unsigned long windowMs) {
    unsigned long now = millis();
    
    if (rateLimits.find(ip) == rateLimits.end()) {
        rateLimits[ip] = {now, 1};
        return true;
    }
    
    RateLimitData& data = rateLimits[ip];
    
    if (now - data.lastRequest > windowMs) {
        data.lastRequest = now;
        data.requestCount = 1;
        return true;
    }
    
    if (data.requestCount >= maxRequests) {
        return false;
    }
    
    data.requestCount++;
    return true;
}

// Apply to sensitive endpoints
server.on("/login", HTTP_POST, []() {
    IPAddress clientIP = server.client().remoteIP();
    
    if (!checkRateLimit(clientIP, 5, 60000)) { // 5 requests per minute
        server.send(429, "text/plain", "Too many requests");
        return;
    }
    
    // Process login...
});
```

**Deliverable:** Rate limiting on authentication and sensitive endpoints

---

### H5: Missing Security Headers
**Required Fix:**
```cpp
void sendSecurityHeaders() {
    server.sendHeader("X-Content-Type-Options", "nosniff");
    server.sendHeader("X-Frame-Options", "DENY");
    server.sendHeader("X-XSS-Protection", "1; mode=block");
    server.sendHeader("Strict-Transport-Security", 
                      "max-age=31536000; includeSubDomains");
    server.sendHeader("Content-Security-Policy", 
                      "default-src 'self'");
}

server.on("/", HTTP_GET, []() {
    if (!requireAuth(server)) return;
    sendSecurityHeaders();
    server.send(200, "text/html", webpage);
});
```

**Deliverable:** Security headers on all responses

---

## MEDIUM PRIORITY ISSUES

### M1: Enable Secure Boot
**Action:** Configure ESP32 secure boot to prevent unauthorized firmware execution.

```ini
# platformio.ini
[env:esp32doit-devkit-v1]
build_flags = 
    -DCONFIG_SECURE_BOOT_ENABLED=1
    -DCONFIG_SECURE_BOOT_V2_ENABLED=1
    -DCONFIG_SECURE_FLASH_ENC_ENABLED=1
```

**Note:** This is a one-time hardware configuration that burns eFuses.

---

### M2: Implement Data Encryption at Rest
**Action:** Encrypt sensitive files on LittleFS.

```cpp
#include <mbedtls/aes.h>

void encryptFile(String filename, const uint8_t* key) {
    File input = LittleFS.open(filename, "r");
    File output = LittleFS.open(filename + ".enc", "w");
    
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 256);
    
    uint8_t block[16];
    while (input.available()) {
        size_t len = input.read(block, 16);
        if (len < 16) {
            memset(block + len, 16 - len, 16 - len); // PKCS7 padding
        }
        
        uint8_t encrypted[16];
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, 
                               block, encrypted);
        output.write(encrypted, 16);
    }
    
    mbedtls_aes_free(&aes);
    input.close();
    output.close();
    LittleFS.remove(filename);
}
```

---

### M3: Add Configuration Integrity Checks
**Action:** Verify configuration files haven't been tampered with.

```cpp
#include <mbedtls/md5.h>

String calculateFileHash(String filename) {
    File file = LittleFS.open(filename, "r");
    
    mbedtls_md5_context ctx;
    mbedtls_md5_init(&ctx);
    mbedtls_md5_starts(&ctx);
    
    uint8_t buffer[128];
    while (file.available()) {
        size_t len = file.read(buffer, 128);
        mbedtls_md5_update(&ctx, buffer, len);
    }
    
    uint8_t hash[16];
    mbedtls_md5_finish(&ctx, hash);
    mbedtls_md5_free(&ctx);
    file.close();
    
    char hashStr[33];
    for(int i = 0; i < 16; i++) {
        sprintf(hashStr + (i * 2), "%02x", hash[i]);
    }
    
    return String(hashStr);
}

void verifyConfigIntegrity() {
    String expectedHash = getStoredHash("wifi_config");
    String actualHash = calculateFileHash("/wifi_config.json");
    
    if (expectedHash != actualHash) {
        Serial.println("WARNING: Configuration tampering detected!");
        // Take action: alert, revert, etc.
    }
}
```

---

### M4: Implement Secure Logging
**Action:** Add access logging without exposing sensitive data.

```cpp
void logAccess(String endpoint, String action, bool success) {
    File log = LittleFS.open("/access.log", "a");
    
    if (log) {
        time_t now = time(nullptr);
        String timestamp = String(now);
        String clientIP = server.client().remoteIP().toString();
        String status = success ? "SUCCESS" : "FAILURE";
        
        String logEntry = timestamp + " | " + 
                         clientIP + " | " + 
                         endpoint + " | " + 
                         action + " | " + 
                         status + "\n";
        
        log.print(logEntry);
        log.close();
    }
}

// Use in handlers
server.on("/download", HTTP_GET, []() {
    if (!requireAuth(server)) {
        logAccess("/download", "DOWNLOAD", false);
        return;
    }
    
    String filename = server.arg("file");
    // ... handle download ...
    
    logAccess("/download", filename, true);
});
```

---

### M5: Certificate Management System
**Action:** Implement automatic certificate renewal.

```cpp
void checkCertificateExpiry() {
    // Parse certificate expiry date
    time_t expiry = getCertificateExpiry();
    time_t now = time(nullptr);
    
    // Renew 30 days before expiry
    if (expiry - now < (30 * 24 * 3600)) {
        Serial.println("Certificate expiring soon, renewing...");
        renewCertificate();
    }
}

void renewCertificate() {
    HTTPClient http;
    WiFiClientSecure client;
    
    http.begin(client, "https://ca.example.com/renew");
    
    // Send CSR for renewal
    String csr = generateCSR();
    int httpCode = http.POST(csr);
    
    if (httpCode == 200) {
        String newCert = http.getString();
        
        // Store new certificate
        prefs.begin("certs", false);
        prefs.putString("device_cert", newCert);
        prefs.end();
        
        Serial.println("Certificate renewed successfully");
    }
    
    http.end();
}
```

---

## TESTING REQUIREMENTS

### Unit Tests Required
```cpp
// Test authentication
void test_authentication() {
    assert(validateSession("invalid_token") == false);
    assert(generateSecureToken().length() == 64);
}

// Test input validation
void test_input_validation() {
    assert(validateSensorId("ABC123") == true);
    assert(validateSensorId("../../../etc") == false);
    assert(validateTemperature("25.5") == true);
    assert(validateTemperature("999") == false);
}

// Test signature verification
void test_firmware_signature() {
    uint8_t testFirmware[] = {...};
    uint8_t validSig[] = {...};
    assert(verifyFirmwareSignature(testFirmware, 
                                    sizeof(testFirmware), 
                                    validSig, 256) == true);
}
```

### Integration Tests
- [ ] HTTPS connection establishment
- [ ] Session creation and validation
- [ ] MQTT TLS connection
- [ ] Firmware upload with signature
- [ ] File access controls

### Security Tests
- [ ] Authentication bypass attempts
- [ ] Path traversal attempts
- [ ] SQL injection in labels (if applicable)
- [ ] Buffer overflow tests
- [ ] Denial of service tests

---

## DEPENDENCIES

### From Security Team
- [ ] Root CA certificate
- [ ] Device certificate signing
- [ ] Firmware signing private key
- [ ] MQTT broker certificates
- [ ] Encryption key management guidelines

### From Backend Team
- [ ] MQTT broker TLS configuration
- [ ] API endpoint for provisioning
- [ ] Certificate renewal API

### From Frontend Team
- [ ] Updated login UI
- [ ] HTTPS compatibility
- [ ] Session handling in JavaScript

---

## DEVELOPMENT GUIDELINES

### Code Style
- Use meaningful variable names
- Add comments for security-critical sections
- Follow ESP32 best practices
- Minimize memory usage

### Security Principles
- **Defense in Depth:** Multiple layers of security
- **Least Privilege:** Minimum necessary permissions
- **Fail Securely:** Default deny, safe error handling
- **Security by Design:** Build security in from start

### Testing Approach
- Test authentication before deployment
- Validate all input sanitization
- Verify TLS connections
- Test rollback scenarios

---

## SUPPORT

**Security Questions:** Contact Security Team Lead  
**Architecture Questions:** Contact Technical Lead  
**Implementation Help:** Post in `#firmware-security` Slack channel

**Documentation:** All changes must be documented in:
- Code comments
- API documentation  
- Security architecture document
- Deployment guide

---

**Report Generated:** Security Audit Team  
**Document Version:** 1.0  
**Last Updated:** December 16, 2025

---

# BACKEND TEAM - Security Remediation Tasks

**Project:** SensorWatch IoT Security Hardening  
**Component:** PHP Backend API (`src/update_db.php`)  
**Audit Date:** October 29, 2025  
**Priority:** CRITICAL - Production Blocker

---

## CRITICAL ISSUES

### C1: SQL Injection Vulnerability
**CVSS Score:** 9.8 | **CWE-89**

**How Discovered:**
Manual SQL injection testing revealed unsanitized user input directly concatenated into SQL queries. Test payload:
```bash
curl -X POST http://ecoforces.com/update_db.php \
  -d "api_key=tPmAT5Ab3j7F9&data=[{\"sensor_id\":\"TEST' OR '1'='1\",\"reading_value\":\"25\"}]"
# SQL syntax error confirms vulnerability
```

**Current Vulnerable Code (lines 64-66):**
```php
$sensor_id = test_input($reading["sensor_id"]);
$reading_value = test_input($reading["reading_value"]);
$values[] = "('$sensor_id', '$reading_value')";

$sql = "INSERT INTO sensor_readings (sensor_id, reading_value) VALUES ";
$sql .= implode(", ", $values);
$conn->query($sql);
```

**The Problem:**
The `test_input()` function only performs XSS prevention:
```php
function test_input($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);  // Does NOT prevent SQL injection!
    return $data;
}
```

**Security Impact:**
- Attacker can extract entire database contents
- Database records can be modified or deleted
- Administrative commands can be executed
- Server files may be readable via `LOAD_FILE()`
- Web shells may be uploaded via `INTO OUTFILE`

**Attack Example:**
```php
// Malicious payload
$payload = [
    "sensor_id" => "' UNION SELECT username, password FROM users WHERE '1'='1",
    "reading_value" => "0"
];

// Resulting SQL:
INSERT INTO sensor_readings (sensor_id, reading_value) 
VALUES ('' UNION SELECT username, password FROM users WHERE '1'='1', '0')
```

**Required Fix:**
Implement prepared statements with parameterized queries:

```php
<?php
header('Content-Type: application/json');
error_reporting(0);
ini_set('display_errors', 0);

// Load configuration from environment variables
$servername = getenv('DB_HOST');
$dbname     = getenv('DB_NAME');
$username   = getenv('DB_USER');
$password   = getenv('DB_PASSWORD');

if (!$servername || !$username || !$password) {
    http_response_code(500);
    die(json_encode(["error" => "Configuration error"]));
}

// Create connection with error handling
$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    error_log("Database connection failed: " . $conn->connect_error);
    http_response_code(500);
    die(json_encode(["error" => "Database connection failed"]));
}

// Validate API key
$api_key = $_POST['api_key'] ?? '';
if (!validateApiKey($api_key)) {
    http_response_code(401);
    die(json_encode(["error" => "Invalid API key"]));
}

// Parse and validate input data
$data_json = $_POST['data'] ?? '';
$data = json_decode($data_json, true);

if (!$data || !is_array($data)) {
    http_response_code(400);
    die(json_encode(["error" => "Invalid data format"]));
}

// Prepare statement ONCE
$stmt = $conn->prepare(
    "INSERT INTO sensor_readings (sensor_id, reading_value, timestamp) 
     VALUES (?, ?, NOW())"
);

if (!$stmt) {
    error_log("Prepare failed: " . $conn->error);
    http_response_code(500);
    die(json_encode(["error" => "Database error"]));
}

$stmt->bind_param("sd", $sensor_id, $reading_value);

$success_count = 0;
$error_count = 0;

foreach ($data as $reading) {
    // Validate each reading
    if (!validateSensorData($reading)) {
        $error_count++;
        continue;
    }
    
    $sensor_id = $reading["sensor_id"];
    $reading_value = floatval($reading["reading_value"]);
    
    if (!$stmt->execute()) {
        error_log("Insert failed: " . $stmt->error);
        $error_count++;
    } else {
        $success_count++;
    }
}

$stmt->close();
$conn->close();

http_response_code(200);
echo json_encode([
    "status" => "success",
    "inserted" => $success_count,
    "errors" => $error_count
]);

// ===== VALIDATION FUNCTIONS =====

function validateApiKey($key) {
    // Load valid API keys from secure storage
    $validKeys = getValidApiKeys();
    return in_array($key, $validKeys, true);
}

function validateSensorData($reading) {
    // Check required fields exist
    if (!isset($reading["sensor_id"]) || !isset($reading["reading_value"])) {
        return false;
    }
    
    // Validate sensor ID format (16 hex characters)
    if (!preg_match('/^[A-F0-9]{16}$/', $reading["sensor_id"])) {
        return false;
    }
    
    // Validate reading value is numeric
    if (!is_numeric($reading["reading_value"])) {
        return false;
    }
    
    // Validate reading range (-50 to 150 Fahrenheit)
    $value = floatval($reading["reading_value"]);
    if ($value < -50 || $value > 150) {
        return false;
    }
    
    return true;
}

function getValidApiKeys() {
    // In production, load from database or environment
    // For now, return array of valid keys
    return [
        getenv('API_KEY_1'),
        getenv('API_KEY_2')
    ];
}
?>
```

**Deliverables:**
- [ ] Rewrite `update_db.php` with prepared statements
- [ ] Implement input validation functions
- [ ] Add proper error handling
- [ ] Remove verbose error messages
- [ ] Add request logging
- [ ] Create SQL injection test suite

**Testing:**
```bash
# Test valid input
curl -X POST http://ecoforces.com/update_db.php \
  -d "api_key=${VALID_KEY}&data=[{\"sensor_id\":\"ABC123DEF4567890\",\"reading_value\":\"72.5\"}]"

# Test SQL injection (should be blocked)
curl -X POST http://ecoforces.com/update_db.php \
  -d "api_key=${VALID_KEY}&data=[{\"sensor_id\":\"' OR '1'='1\",\"reading_value\":\"0\"}]"
# Expected: 400 Bad Request - Invalid sensor ID format
```

---

### C2: Hardcoded Database Credentials
**CVSS Score:** 10.0 | **CWE-798**

**How Discovered:**
Source code review revealed database credentials embedded in PHP file (lines 15-18):

```php
$servername = "db5017073076.hosting-data.io";
$dbname     = "dbs13737298";
$username   = "dbu5607697";
$password   = "WinWinLabs2025!!";
```

**Security Impact:**
- Anyone with repository access can access production database
- Credentials cannot be rotated without code changes
- Same credentials used across all environments
- Password exposed in version control history

**Required Fix:**
Move credentials to environment variables:

```php
<?php
// Load from environment variables
$servername = getenv('DB_HOST');
$dbname     = getenv('DB_NAME');
$username   = getenv('DB_USER');
$password   = getenv('DB_PASSWORD');

// Validate all credentials are present
if (!$servername || !$dbname || !$username || !$password) {
    error_log("Missing required database configuration");
    http_response_code(500);
    die(json_encode(["error" => "Configuration error"]));
}

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    error_log("Connection failed: " . $conn->connect_error);
    http_response_code(500);
    die(json_encode(["error" => "Database connection failed"]));
}
?>
```

**Environment Configuration:**

For Apache (`.htaccess` or `httpd.conf`):
```apache
SetEnv DB_HOST "db5017073076.hosting-data.io"
SetEnv DB_NAME "dbs13737298"
SetEnv DB_USER "sensor_app_user"
SetEnv DB_PASSWORD "NEW_SECURE_PASSWORD_HERE"
```

For Nginx (`nginx.conf`):
```nginx
location ~ \.php$ {
    fastcgi_param DB_HOST "db5017073076.hosting-data.io";
    fastcgi_param DB_NAME "dbs13737298";
    fastcgi_param DB_USER "sensor_app_user";
    fastcgi_param DB_PASSWORD "NEW_SECURE_PASSWORD_HERE";
}
```

For Docker:
```dockerfile
# docker-compose.yml
services:
  web:
    environment:
      - DB_HOST=db5017073076.hosting-data.io
      - DB_NAME=dbs13737298
      - DB_USER=sensor_app_user
      - DB_PASSWORD_FILE=/run/secrets/db_password
    secrets:
      - db_password

secrets:
  db_password:
    external: true
```

**Best Practice - AWS Secrets Manager:**
```php
<?php
require 'vendor/autoload.php';

use Aws\SecretsManager\SecretsManagerClient;

function getDatabaseCredentials() {
    $client = new SecretsManagerClient([
        'version' => 'latest',
        'region' => 'us-east-1'
    ]);
    
    try {
        $result = $client->getSecretValue([
            'SecretId' => 'prod/sensorwatch/database'
        ]);
        
        $secret = json_decode($result['SecretString'], true);
        
        return [
            'host' => $secret['host'],
            'database' => $secret['database'],
            'username' => $secret['username'],
            'password' => $secret['password']
        ];
    } catch (Exception $e) {
        error_log("Failed to retrieve secrets: " . $e->getMessage());
        return null;
    }
}

$credentials = getDatabaseCredentials();
if (!$credentials) {
    http_response_code(500);
    die(json_encode(["error" => "Configuration error"]));
}

$conn = new mysqli(
    $credentials['host'],
    $credentials['username'],
    $credentials['password'],
    $credentials['database']
);
?>
```

**Deliverables:**
- [ ] Remove hardcoded credentials from source code
- [ ] Configure environment variables
- [ ] Update deployment documentation
- [ ] Implement credential rotation procedure
- [ ] Verify credentials not in Git history (use `git filter-branch` if needed)

**Credential Rotation Procedure:**
1. Create new database user with same permissions
2. Update environment variables with new credentials
3. Reload web server configuration
4. Verify application functionality
5. Revoke old database user
6. Document change in security log

---

## HIGH PRIORITY ISSUES

### H1: Static API Key Authentication
**How Discovered:**
API key is hardcoded in firmware source code and never rotates:
```cpp
// From ESP32 firmware
String remoteApiKey = "tPmAT5Ab3j7F9";
```

**Security Impact:**
- Single compromised device exposes API key for all devices
- No ability to revoke compromised keys
- No rate limiting per device
- Cannot track which device made which requests

**Required Fix:**
Implement device-specific API key system with rotation capability.

**Database Schema:**
```sql
CREATE TABLE api_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    device_id VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    last_used TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    rate_limit_per_hour INT DEFAULT 1000,
    INDEX idx_key_hash (key_hash),
    INDEX idx_device_id (device_id),
    INDEX idx_active (is_active)
);

CREATE TABLE api_key_usage (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    key_id INT NOT NULL,
    request_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    endpoint VARCHAR(255),
    success BOOLEAN,
    INDEX idx_key_time (key_id, request_time),
    FOREIGN KEY (key_id) REFERENCES api_keys(id)
);
```

**API Key Management Functions:**
```php
<?php
function generateApiKey() {
    // Generate cryptographically secure random key
    $randomBytes = random_bytes(32);
    return bin2hex($randomBytes);
}

function hashApiKey($key) {
    return hash('sha256', $key);
}

function validateApiKey($providedKey) {
    global $conn;
    
    $keyHash = hashApiKey($providedKey);
    
    $stmt = $conn->prepare(
        "SELECT id, device_id, expires_at, is_active, rate_limit_per_hour 
         FROM api_keys 
         WHERE key_hash = ? AND is_active = TRUE"
    );
    
    $stmt->bind_param("s", $keyHash);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        $stmt->close();
        return null;
    }
    
    $keyData = $result->fetch_assoc();
    $stmt->close();
    
    // Check expiration
    if ($keyData['expires_at'] && strtotime($keyData['expires_at']) < time()) {
        return null;
    }
    
    // Check rate limit
    if (!checkRateLimit($keyData['id'], $keyData['rate_limit_per_hour'])) {
        http_response_code(429);
        die(json_encode(["error" => "Rate limit exceeded"]));
    }
    
    // Update last used
    $updateStmt = $conn->prepare(
        "UPDATE api_keys SET last_used = NOW() WHERE id = ?"
    );
    $updateStmt->bind_param("i", $keyData['id']);
    $updateStmt->execute();
    $updateStmt->close();
    
    // Log usage
    logApiKeyUsage($keyData['id'], $_SERVER['REQUEST_URI'], true);
    
    return $keyData;
}

function checkRateLimit($keyId, $maxRequestsPerHour) {
    global $conn;
    
    $stmt = $conn->prepare(
        "SELECT COUNT(*) as request_count 
         FROM api_key_usage 
         WHERE key_id = ? 
         AND request_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)"
    );
    
    $stmt->bind_param("i", $keyId);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    $stmt->close();
    
    return $row['request_count'] < $maxRequestsPerHour;
}

function logApiKeyUsage($keyId, $endpoint, $success) {
    global $conn;
    
    $stmt = $conn->prepare(
        "INSERT INTO api_key_usage (key_id, endpoint, success) 
         VALUES (?, ?, ?)"
    );
    
    $stmt->bind_param("isi", $keyId, $endpoint, $success);
    $stmt->execute();
    $stmt->close();
}

function revokeApiKey($keyHash) {
    global $conn;
    
    $stmt = $conn->prepare(
        "UPDATE api_keys SET is_active = FALSE WHERE key_hash = ?"
    );
    
    $stmt->bind_param("s", $keyHash);
    $success = $stmt->execute();
    $stmt->close();
    
    return $success;
}
?>
```

**Updated Main Handler:**
```php
<?php
// Validate API key
$providedKey = $_POST['api_key'] ?? '';
$keyData = validateApiKey($providedKey);

if (!$keyData) {
    http_response_code(401);
    die(json_encode(["error" => "Invalid or expired API key"]));
}

// Continue with request processing...
// $keyData['device_id'] can be used for device-specific logic
?>
```

**API Key Generation Endpoint:**
```php
<?php
// admin_generate_key.php - Requires admin authentication

session_start();
if (!isset($_SESSION['admin_authenticated'])) {
    http_response_code(401);
    die(json_encode(["error" => "Unauthorized"]));
}

$deviceId = $_POST['device_id'] ?? '';
if (empty($deviceId)) {
    http_response_code(400);
    die(json_encode(["error" => "Device ID required"]));
}

// Generate new API key
$apiKey = generateApiKey();
$keyHash = hashApiKey($apiKey);

// Set expiration (e.g., 1 year from now)
$expiresAt = date('Y-m-d H:i:s', strtotime('+1 year'));

// Store in database
$stmt = $conn->prepare(
    "INSERT INTO api_keys (key_hash, device_id, expires_at) 
     VALUES (?, ?, ?)"
);

$stmt->bind_param("sss", $keyHash, $deviceId, $expiresAt);

if ($stmt->execute()) {
    echo json_encode([
        "status" => "success",
        "api_key" => $apiKey,  // Only shown once!
        "device_id" => $deviceId,
        "expires_at" => $expiresAt
    ]);
} else {
    http_response_code(500);
    echo json_encode(["error" => "Failed to generate key"]);
}

$stmt->close();
?>
```

**Deliverables:**
- [ ] Create API key management database tables
- [ ] Implement key validation with rate limiting
- [ ] Create key generation endpoint
- [ ] Implement key revocation capability
- [ ] Add usage tracking and monitoring
- [ ] Document key rotation procedure

**Dependencies:** Firmware team (update devices with new keys)

---

### H2: HTTP Instead of HTTPS
**How Discovered:**
Backend API accessible via unencrypted HTTP:
```bash
curl http://ecoforces.com/update_db.php
# Connection succeeds without TLS
```

**Security Impact:**
- API keys transmitted in cleartext
- Sensor data exposed to eavesdropping
- Man-in-the-middle attacks possible
- Session hijacking (if sessions implemented)

**Required Fix:**
Enable HTTPS with TLS certificate and enforce HTTPS-only access.

**Apache Configuration:**
```apache
<VirtualHost *:80>
    ServerName ecoforces.com
    
    # Redirect all HTTP to HTTPS
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</VirtualHost>

<VirtualHost *:443>
    ServerName ecoforces.com
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/ecoforces.com.crt
    SSLCertificateKeyFile /etc/ssl/private/ecoforces.com.key
    SSLCertificateChainFile /etc/ssl/certs/intermediate.crt
    
    # Modern SSL configuration
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    SSLCipherSuite HIGH:!aNULL:!MD5
    SSLHonorCipherOrder on
    
    # HSTS Header
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    
    DocumentRoot /var/www/html
    
    <Directory /var/www/html>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

**Nginx Configuration:**
```nginx
server {
    listen 80;
    server_name ecoforces.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ecoforces.com;
    
    # SSL Configuration
    ssl_certificate /etc/ssl/certs/ecoforces.com.crt;
    ssl_certificate_key /etc/ssl/private/ecoforces.com.key;
    ssl_trusted_certificate /etc/ssl/certs/ca-chain.crt;
    
    # Modern SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    root /var/www/html;
    index index.php;
    
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }
}
```

**Obtain SSL Certificate (Let's Encrypt):**
```bash
# Install Certbot
sudo apt-get update
sudo apt-get install certbot python3-certbot-apache

# Obtain certificate
sudo certbot --apache -d ecoforces.com -d www.ecoforces.com

# Auto-renewal (add to crontab)
0 0 * * * certbot renew --quiet
```

**PHP Security Headers:**
```php
<?php
// Add at the beginning of update_db.php

// Ensure HTTPS
if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
    header('Location: https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
    exit();
}

// Security headers
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Content-Security-Policy: default-src \'self\'');
?>
```

**Deliverables:**
- [ ] Obtain SSL/TLS certificate
- [ ] Configure web server for HTTPS
- [ ] Implement HTTP to HTTPS redirect
- [ ] Add HSTS header
- [ ] Configure automatic certificate renewal
- [ ] Update DNS records if needed
- [ ] Test certificate chain

**Dependencies:** Firmware team (update API endpoint URLs to HTTPS)

---

### H3: Input Validation Gaps
**How Discovered:**
Testing revealed multiple input validation issues beyond SQL injection.

**Required Fix:**
Comprehensive input validation for all parameters.

```php
<?php
class InputValidator {
    
    public static function validateSensorId($sensorId) {
        // Must be exactly 16 hexadecimal characters
        if (!preg_match('/^[A-F0-9]{16}$/', $sensorId)) {
            return [
                'valid' => false,
                'error' => 'Invalid sensor ID format'
            ];
        }
        
        return ['valid' => true];
    }
    
    public static function validateReadingValue($value) {
        // Must be numeric
        if (!is_numeric($value)) {
            return [
                'valid' => false,
                'error' => 'Reading value must be numeric'
            ];
        }
        
        $floatValue = floatval($value);
        
        // Temperature range: -50°F to 150°F
        if ($floatValue < -50 || $floatValue > 150) {
            return [
                'valid' => false,
                'error' => 'Reading value out of valid range'
            ];
        }
        
        return [
            'valid' => true,
            'value' => $floatValue
        ];
    }
    
    public static function validateTimestamp($timestamp) {
        // ISO 8601 format
        $pattern = '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/';
        
        if (!preg_match($pattern, $timestamp)) {
            return [
                'valid' => false,
                'error' => 'Invalid timestamp format'
            ];
        }
        
        // Verify it's a valid date
        $time = strtotime($timestamp);
        if ($time === false) {
            return [
                'valid' => false,
                'error' => 'Invalid timestamp'
            ];
        }
        
        // Reject timestamps more than 1 hour in the future
        if ($time > time() + 3600) {
            return [
                'valid' => false,
                'error' => 'Timestamp too far in the future'
            ];
        }
        
        return [
            'valid' => true,
            'value' => $time
        ];
    }
    
    public static function validateApiKey($key) {
        // Must be 64 hexadecimal characters
        if (!preg_match('/^[a-f0-9]{64}$/', $key)) {
            return [
                'valid' => false,
                'error' => 'Invalid API key format'
            ];
        }
        
        return ['valid' => true];
    }
    
    public static function sanitizeOutput($text) {
        return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    }
}

// Usage in main handler
$data_json = $_POST['data'] ?? '';

// Validate JSON structure
$data = json_decode($data_json, true);
if (json_last_error() !== JSON_ERROR_NONE) {
    http_response_code(400);
    die(json_encode([
        "error" => "Invalid JSON format",
        "details" => json_last_error_msg()
    ]));
}

if (!is_array($data) || count($data) === 0) {
    http_response_code(400);
    die(json_encode(["error" => "Data must be a non-empty array"]));
}

// Limit batch size
if (count($data) > 100) {
    http_response_code(400);
    die(json_encode(["error" => "Maximum 100 readings per request"]));
}

// Validate each reading
foreach ($data as $reading) {
    // Validate sensor_id
    $sensorIdValidation = InputValidator::validateSensorId(
        $reading["sensor_id"] ?? ''
    );
    if (!$sensorIdValidation['valid']) {
        http_response_code(400);
        die(json_encode(["error" => $sensorIdValidation['error']]));
    }
    
    // Validate reading_value
    $valueValidation = InputValidator::validateReadingValue(
        $reading["reading_value"] ?? ''
    );
    if (!$valueValidation['valid']) {
        http_response_code(400);
        die(json_encode(["error" => $valueValidation['error']]));
    }
    
    // Optional: Validate timestamp if provided
    if (isset($reading["timestamp"])) {
        $timestampValidation = InputValidator::validateTimestamp(
            $reading["timestamp"]
        );
        if (!$timestampValidation['valid']) {
            http_response_code(400);
            die(json_encode(["error" => $timestampValidation['error']]));
        }
    }
}
?>
```

**Deliverables:**
- [ ] Create InputValidator class
- [ ] Implement validation for all parameters
- [ ] Add batch size limits
- [ ] Add JSON validation
- [ ] Implement sanitization for outputs
- [ ] Add validation unit tests

---

### H4: Error Information Disclosure
**How Discovered:**
Verbose error messages expose internal system details:
```bash
curl -X POST http://ecoforces.com/update_db.php -d "invalid=data"
# Returns: "mysqli_connect(): Access denied for user 'dbu5607697'@'192.168.1.100'"
```

**Security Impact:**
- Database structure and usernames exposed
- File paths revealed
- Technology stack disclosed
- Aids attackers in reconnaissance

**Required Fix:**
Implement generic error messages for users, detailed logging for developers.

```php
<?php
// Disable error display in production
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', '/var/log/php/sensorwatch_errors.log');

// Custom error handler
function customErrorHandler($errno, $errstr, $errfile, $errline) {
    // Log detailed error for developers
    $errorMessage = sprintf(
        "[%s] Error %d: %s in %s on line %d",
        date('Y-m-d H:i:s'),
        $errno,
        $errstr,
        $errfile,
        $errline
    );
    
    error_log($errorMessage);
    
    // Return generic message to user
    http_response_code(500);
    echo json_encode([
        "error" => "An internal error occurred",
        "error_id" => uniqid('err_', true)  // Reference ID for support
    ]);
    
    exit();
}

set_error_handler("customErrorHandler");

// Custom exception handler
function customExceptionHandler($exception) {
    $errorMessage = sprintf(
        "[%s] Exception: %s in %s on line %d\nStack trace:\n%s",
        date('Y-m-d H:i:s'),
        $exception->getMessage(),
        $exception->getFile(),
        $exception->getLine(),
        $exception->getTraceAsString()
    );
    
    error_log($errorMessage);
    
    http_response_code(500);
    echo json_encode([
        "error" => "An internal error occurred",
        "error_id" => uniqid('err_', true)
    ]);
    
    exit();
}

set_exception_handler("customExceptionHandler");

// Database connection with error handling
try {
    $conn = new mysqli($servername, $username, $password, $dbname);
    
    if ($conn->connect_error) {
        throw new Exception("Database connection failed");
    }
} catch (Exception $e) {
    error_log("Database connection error: " . $e->getMessage());
    http_response_code(500);
    die(json_encode(["error" => "Database connection failed"]));
}

// Query execution with error handling
try {
    if (!$stmt->execute()) {
        throw new Exception("Query execution failed: " . $stmt->error);
    }
} catch (Exception $e) {
    error_log("Query error: " . $e->getMessage());
    http_response_code(500);
    die(json_encode(["error" => "Data processing failed"]));
}
?>
```

**Production php.ini Settings:**
```ini
; Error handling
display_errors = Off
display_startup_errors = Off
log_errors = On
error_log = /var/log/php/errors.log

; Error reporting
error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT

; Disable exposing PHP version
expose_php = Off
```

**Deliverables:**
- [ ] Implement custom error handlers
- [ ] Configure production error settings
- [ ] Set up centralized error logging
- [ ] Create error log rotation
- [ ] Add error monitoring/alerting

---

## MEDIUM PRIORITY ISSUES

### M1: Request/Response Logging
**Action:** Implement comprehensive logging for security monitoring.

```php
<?php
class SecurityLogger {
    private $logFile = '/var/log/php/sensorwatch_security.log';
    
    public function logRequest() {
        $logEntry = [
            'timestamp' => date('c'),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'method' => $_SERVER['REQUEST_METHOD'] ?? 'unknown',
            'uri' => $_SERVER['REQUEST_URI'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'api_key_hash' => isset($_POST['api_key']) ? 
                substr(hash('sha256', $_POST['api_key']), 0, 8) : 'none'
        ];
        
        file_put_contents(
            $this->logFile,
            json_encode($logEntry) . PHP_EOL,
            FILE_APPEND | LOCK_EX
        );
    }
    
    public function logSecurityEvent($event, $details = []) {
        $logEntry = [
            'timestamp' => date('c'),
            'event' => $event,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'details' => $details
        ];
        
        file_put_contents(
            $this->logFile,
            '[SECURITY] ' . json_encode($logEntry) . PHP_EOL,
            FILE_APPEND | LOCK_EX
        );
    }
}

// Usage
$logger = new SecurityLogger();
$logger->logRequest();

// Log security events
if (!$keyData) {
    $logger->logSecurityEvent('invalid_api_key', [
        'provided_key' => substr($_POST['api_key'], 0, 8) . '...'
    ]);
}
?>
```

---

### M2: Add Response Time Monitoring
**Action:** Track API performance for anomaly detection.

```php
<?php
$requestStartTime = microtime(true);

// ... process request ...

$requestEndTime = microtime(true);
$processingTime = ($requestEndTime - $requestStartTime) * 1000; // milliseconds

// Log slow requests
if ($processingTime > 1000) { // > 1 second
    error_log(sprintf(
        "Slow request: %s ms for %s",
        $processingTime,
        $_SERVER['REQUEST_URI']
    ));
}

// Add to response header for monitoring
header('X-Processing-Time: ' . $processingTime . 'ms');
?>
```

---

### M3: Implement API Versioning
**Action:** Support multiple API versions for backward compatibility.

```php
<?php
// v1/update_db.php
$apiVersion = 'v1';

// v2/update_db.php (future)
$apiVersion = 'v2';

// Support version in URL or header
$requestedVersion = $_GET['version'] ?? 
                    $_SERVER['HTTP_API_VERSION'] ?? 
                    'v1';

if ($requestedVersion !== $apiVersion) {
    http_response_code(400);
    die(json_encode([
        "error" => "API version mismatch",
        "requested" => $requestedVersion,
        "supported" => [$apiVersion]
    ]));
}
?>
```

---

## TESTING REQUIREMENTS

### Unit Tests
```php
<?php
// tests/InputValidatorTest.php
use PHPUnit\Framework\TestCase;

class InputValidatorTest extends TestCase {
    public function testValidSensorId() {
        $result = InputValidator::validateSensorId('ABC123DEF4567890');
        $this->assertTrue($result['valid']);
    }
    
    public function testInvalidSensorId() {
        $result = InputValidator::validateSensorId("' OR '1'='1");
        $this->assertFalse($result['valid']);
    }
    
    public function testSQLInjectionPrevention() {
        $malicious = "'; DROP TABLE sensor_readings; --";
        $result = InputValidator::validateSensorId($malicious);
        $this->assertFalse($result['valid']);
    }
    
    public function testValidReadingValue() {
        $result = InputValidator::validateReadingValue('72.5');
        $this->assertTrue($result['valid']);
        $this->assertEquals(72.5, $result['value']);
    }
    
    public function testInvalidReadingValue() {
        $result = InputValidator::validateReadingValue('999');
        $this->assertFalse($result['valid']);
    }
}
?>
```

### Integration Tests
```bash
#!/bin/bash
# tests/integration_test.sh

API_URL="https://ecoforces.com/update_db.php"
VALID_API_KEY="your_test_api_key_here"

# Test valid request
echo "Testing valid request..."
curl -X POST "$API_URL" \
  -d "api_key=$VALID_API_KEY&data=[{\"sensor_id\":\"ABC123DEF4567890\",\"reading_value\":\"72.5\"}]"

# Test SQL injection (should be blocked)
echo "Testing SQL injection protection..."
curl -X POST "$API_URL" \
  -d "api_key=$VALID_API_KEY&data=[{\"sensor_id\":\"' OR '1'='1\",\"reading_value\":\"0\"}]"
# Expected: 400 Bad Request

# Test invalid API key
echo "Testing invalid API key..."
curl -X POST "$API_URL" \
  -d "api_key=invalid_key&data=[{\"sensor_id\":\"ABC123DEF4567890\",\"reading_value\":\"72.5\"}]"
# Expected: 401 Unauthorized

# Test rate limiting
echo "Testing rate limiting..."
for i in {1..100}; do
  curl -X POST "$API_URL" \
    -d "api_key=$VALID_API_KEY&data=[{\"sensor_id\":\"TEST\",\"reading_value\":\"25\"}]"
done
# Should eventually return 429 Too Many Requests
```

---

## DEPENDENCIES

### From Database Team
- [ ] Create limited database user
- [ ] Grant only INSERT/SELECT permissions
- [ ] Enable database auditing
- [ ] Provide connection encryption configuration

### From Security Team
- [ ] SSL/TLS certificate for HTTPS
- [ ] API key management guidelines
- [ ] Secrets management solution
- [ ] Security monitoring integration

### From Firmware Team
- [ ] Update API endpoint URLs to HTTPS
- [ ] Implement new API key format
- [ ] Add error handling for 401/429 responses

---

## DEPLOYMENT CHECKLIST

- [ ] Update `update_db.php` with all fixes
- [ ] Configure environment variables
- [ ] Enable HTTPS and obtain certificate
- [ ] Create API key management tables
- [ ] Generate device-specific API keys
- [ ] Update database user permissions
- [ ] Configure error logging
- [ ] Set up monitoring and alerting
- [ ] Test all endpoints
- [ ] Update documentation
- [ ] Notify firmware team of changes

---

**Report Generated:** Security Audit Team  
**Document Version:** 1.0  
**Last Updated:** December 16, 2025

---

# SECURITY TEAM - Security Remediation Tasks

**Project:** SensorWatch IoT Security Hardening  
**Component:** Cross-System Security Architecture  
**Audit Date:** October 29, 2025  
**Priority:** CRITICAL - Foundation for All Security Controls

---

## OVERVIEW

The Security Team is responsible for establishing security infrastructure that enables all other teams to implement security controls. Your work is the foundation upon which firmware, backend, database, and frontend security depends.

**Key Responsibilities:**
- Certificate management (PKI)
- Key management and rotation
- Secrets management infrastructure
- Security monitoring and alerting
- Threat modeling and risk assessment
- Security testing framework
- Incident response procedures

---

## CRITICAL PRIORITY TASKS

### C1: Establish Public Key Infrastructure (PKI)
**Dependencies:** All teams require certificates

**How Discovered:**
Multiple systems require TLS/SSL certificates but no certificate authority exists:
- Firmware web server needs HTTPS certificates
- MQTT broker needs TLS certificates
- Backend API needs SSL certificates
- Firmware signing requires code signing certificates

**Required Actions:**

#### 1. Set Up Certificate Authority

**Create Root CA:**
```bash
# Generate root CA private key (keep offline in secure location)
openssl genrsa -aes256 -out root-ca.key 4096

# Generate root CA certificate (10 year validity)
openssl req -x509 -new -nodes -key root-ca.key \
  -sha256 -days 3650 -out root-ca.crt \
  -subj "/C=US/ST=State/O=WinWinLabs/CN=WinWinLabs Root CA"

# Store root key in secure hardware or vault
```

**Create Intermediate CA:**
```bash
# Generate intermediate CA private key
openssl genrsa -aes256 -out intermediate-ca.key 4096

# Create intermediate CA certificate signing request
openssl req -new -key intermediate-ca.key \
  -out intermediate-ca.csr \
  -subj "/C=US/ST=State/O=WinWinLabs/CN=WinWinLabs Intermediate CA"

# Sign intermediate CA with root CA
openssl x509 -req -in intermediate-ca.csr \
  -CA root-ca.crt -CAkey root-ca.key \
  -CAcreateserial -out intermediate-ca.crt \
  -days 1825 -sha256 \
  -extfile <(cat <<EOF
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
EOF
)

# Create certificate chain
cat intermediate-ca.crt root-ca.crt > ca-chain.crt
```

#### 2. Certificate Issuance Process

**Web Server Certificates:**
```bash
#!/bin/bash
# scripts/issue-server-cert.sh

DOMAIN=$1
DAYS=365

# Generate private key
openssl genrsa -out ${DOMAIN}.key 2048

# Create CSR
openssl req -new -key ${DOMAIN}.key \
  -out ${DOMAIN}.csr \
  -subj "/C=US/ST=State/O=WinWinLabs/CN=${DOMAIN}"

# Sign with intermediate CA
openssl x509 -req -in ${DOMAIN}.csr \
  -CA intermediate-ca.crt -CAkey intermediate-ca.key \
  -CAcreateserial -out ${DOMAIN}.crt \
  -days ${DAYS} -sha256 \
  -extfile <(cat <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${DOMAIN},DNS:*.${DOMAIN}
EOF
)

echo "Certificate issued for ${DOMAIN}"
echo "Files created:"
echo "  - ${DOMAIN}.key (private key - keep secure!)"
echo "  - ${DOMAIN}.crt (certificate)"
echo "  - Use ca-chain.crt for certificate chain"
```

**Device Certificates (for MQTT mutual TLS):**
```bash
#!/bin/bash
# scripts/issue-device-cert.sh

DEVICE_ID=$1
DAYS=730  # 2 years

# Generate device private key
openssl genrsa -out device-${DEVICE_ID}.key 2048

# Create CSR with device ID as CN
openssl req -new -key device-${DEVICE_ID}.key \
  -out device-${DEVICE_ID}.csr \
  -subj "/C=US/ST=State/O=WinWinLabs/OU=Devices/CN=${DEVICE_ID}"

# Sign with intermediate CA
openssl x509 -req -in device-${DEVICE_ID}.csr \
  -CA intermediate-ca.crt -CAkey intermediate-ca.key \
  -CAcreateserial -out device-${DEVICE_ID}.crt \
  -days ${DAYS} -sha256 \
  -extfile <(cat <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF
)

echo "Device certificate issued for ${DEVICE_ID}"
```

**Code Signing Certificates:**
```bash
#!/bin/bash
# scripts/issue-codesigning-cert.sh

PURPOSE=$1  # e.g., "firmware-signing"
DAYS=1095  # 3 years

openssl genrsa -out ${PURPOSE}.key 2048

openssl req -new -key ${PURPOSE}.key \
  -out ${PURPOSE}.csr \
  -subj "/C=US/ST=State/O=WinWinLabs/OU=Development/CN=${PURPOSE}"

openssl x509 -req -in ${PURPOSE}.csr \
  -CA intermediate-ca.crt -CAkey intermediate-ca.key \
  -CAcreateserial -out ${PURPOSE}.crt \
  -days ${DAYS} -sha256 \
  -extfile <(cat <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
EOF
)

echo "Code signing certificate issued for ${PURPOSE}"
echo "IMPORTANT: Store private key securely - it will be used in CI/CD"
```

#### 3. Certificate Management System

**Certificate Inventory:**
```sql
CREATE TABLE certificates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    common_name VARCHAR(255) NOT NULL,
    certificate_type ENUM('server', 'device', 'code_signing') NOT NULL,
    serial_number VARCHAR(100) NOT NULL UNIQUE,
    issued_date DATETIME NOT NULL,
    expiry_date DATETIME NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    revocation_date DATETIME NULL,
    revocation_reason VARCHAR(255) NULL,
    INDEX idx_expiry (expiry_date),
    INDEX idx_common_name (common_name)
);

CREATE TABLE certificate_renewals (
    id INT AUTO_INCREMENT PRIMARY KEY,
    certificate_id INT NOT NULL,
    old_serial_number VARCHAR(100) NOT NULL,
    new_serial_number VARCHAR(100) NOT NULL,
    renewal_date DATETIME NOT NULL,
    FOREIGN KEY (certificate_id) REFERENCES certificates(id)
);
```

**Certificate Monitoring Script:**
```python
#!/usr/bin/env python3
# scripts/monitor-certificates.py

import OpenSSL
import datetime
import sys

def check_certificate_expiry(cert_file, warning_days=30):
    """Check if certificate is expiring soon"""
    with open(cert_file, 'rb') as f:
        cert_data = f.read()
    
    cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, cert_data
    )
    
    # Get expiry date
    expiry_str = cert.get_notAfter().decode('utf-8')
    expiry_date = datetime.datetime.strptime(
        expiry_str, '%Y%m%d%H%M%SZ'
    )
    
    # Calculate days until expiry
    days_until_expiry = (expiry_date - datetime.datetime.now()).days
    
    # Get subject
    subject = dict(cert.get_subject().get_components())
    cn = subject.get(b'CN', b'Unknown').decode('utf-8')
    
    print(f"Certificate: {cn}")
    print(f"Expires: {expiry_date}")
    print(f"Days until expiry: {days_until_expiry}")
    
    if days_until_expiry < 0:
        print("⚠️  EXPIRED")
        return False
    elif days_until_expiry < warning_days:
        print(f"⚠️  WARNING: Expiring in {days_until_expiry} days")
        return False
    else:
        print("✓ Valid")
        return True

if __name__ == "__main__":
    cert_file = sys.argv[1]
    check_certificate_expiry(cert_file)
```

**Deliverables:**
- [ ] Root and intermediate CA established
- [ ] Certificate issuance scripts created
- [ ] Certificate inventory database
- [ ] Certificate monitoring system
- [ ] Certificate renewal procedures documented
- [ ] Revocation list (CRL) infrastructure

**Dependencies Fulfilled:**
- Firmware team: Certificates for HTTPS and firmware signing
- Backend team: SSL certificates for API
- Infrastructure: MQTT broker certificates

---

### C2: Implement Secrets Management System
**Dependencies:** All teams need secure credential storage

**How Discovered:**
Multiple systems have hardcoded credentials that need secure storage:
- Database passwords
- API keys
- Encryption keys
- Certificate private keys

**Required Actions:**

#### 1. Choose and Deploy Secrets Manager

**Option A: HashiCorp Vault (Recommended for Production)**

**Installation:**
```bash
# Docker deployment
docker run -d --name vault \
  --cap-add=IPC_LOCK \
  -p 8200:8200 \
  -e 'VAULT_DEV_ROOT_TOKEN_ID=root' \
  -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' \
  vault:latest

# Production deployment with TLS
docker run -d --name vault \
  --cap-add=IPC_LOCK \
  -p 8200:8200 \
  -v /path/to/config:/vault/config \
  -v /path/to/data:/vault/data \
  -v /path/to/logs:/vault/logs \
  vault:latest server
```

**Vault Configuration:**
```hcl
# /vault/config/vault.hcl

storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_cert_file = "/vault/config/vault.crt"
  tls_key_file  = "/vault/config/vault.key"
}

api_addr = "https://vault.example.com:8200"
cluster_addr = "https://vault.example.com:8201"
ui = true
```

**Initialize Vault:**
```bash
# Initialize (save unseal keys securely!)
vault operator init

# Unseal (requires 3 of 5 keys by default)
vault operator unseal <key1>
vault operator unseal <key2>
vault operator unseal <key3>

# Login with root token
vault login <root_token>
```

#### 2. Secret Storage Structure

**Database Credentials:**
```bash
# Store database credentials
vault kv put secret/sensorwatch/database \
  host=db5017073076.hosting-data.io \
  database=dbs13737298 \
  username=sensor_app_user \
  password="<secure-random-password>"

# Store read-only credentials
vault kv put secret/sensorwatch/database-readonly \
  host=db5017073076.hosting-data.io \
  database=dbs13737298 \
  username=sensor_readonly_user \
  password="<secure-random-password>"
```

**API Keys:**
```bash
# Store master API key encryption key
vault kv put secret/sensorwatch/api \
  encryption_key="<32-byte-hex-key>" \
  signing_key="<signing-key>"

# Store device-specific keys (example)
vault kv put secret/sensorwatch/devices/esp32-001 \
  api_key="<device-specific-key>" \
  mqtt_username="esp32-001" \
  mqtt_password="<mqtt-password>"
```

**Encryption Keys:**
```bash
# Encryption keys for data at rest
vault kv put secret/sensorwatch/encryption \
  file_encryption_key="<256-bit-key>" \
  backup_encryption_key="<256-bit-key>"
```

**Certificate Private Keys:**
```bash
# Store certificate private keys
vault kv put secret/sensorwatch/certificates/web \
  private_key=@/path/to/web-server.key

vault kv put secret/sensorwatch/certificates/mqtt \
  private_key=@/path/to/mqtt-broker.key
```

#### 3. Access Control Policies

**Policy for Backend API:**
```hcl
# policies/backend-api.hcl

# Read database credentials
path "secret/data/sensorwatch/database" {
  capabilities = ["read"]
}

# Read API key configuration
path "secret/data/sensorwatch/api" {
  capabilities = ["read"]
}
```

**Policy for Firmware Build System:**
```hcl
# policies/firmware-build.hcl

# Read firmware signing certificate
path "secret/data/sensorwatch/certificates/firmware-signing" {
  capabilities = ["read"]
}

# Read encryption keys
path "secret/data/sensorwatch/encryption" {
  capabilities = ["read"]
}
```

**Apply Policies:**
```bash
vault policy write backend-api policies/backend-api.hcl
vault policy write firmware-build policies/firmware-build.hcl
```

#### 4. Application Integration

**Backend PHP Integration:**
```php
<?php
// lib/VaultClient.php

class VaultClient {
    private $vaultAddr;
    private $token;
    
    public function __construct() {
        $this->vaultAddr = getenv('VAULT_ADDR') ?: 'https://vault.example.com:8200';
        $this->token = getenv('VAULT_TOKEN');
        
        if (!$this->token) {
            throw new Exception("VAULT_TOKEN not set");
        }
    }
    
    public function getSecret($path) {
        $ch = curl_init();
        
        curl_setopt_array($ch, [
            CURLOPT_URL => $this->vaultAddr . '/v1/' . $path,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'X-Vault-Token: ' . $this->token
            ],
            CURLOPT_SSL_VERIFYPEER => true
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        curl_close($ch);
        
        if ($httpCode !== 200) {
            throw new Exception("Failed to retrieve secret: HTTP $httpCode");
        }
        
        $data = json_decode($response, true);
        return $data['data']['data'] ?? null;
    }
    
    public function getDatabaseCredentials() {
        return $this->getSecret('secret/data/sensorwatch/database');
    }
}

// Usage in update_db.php
$vault = new VaultClient();
$dbCreds = $vault->getDatabaseCredentials();

$conn = new mysqli(
    $dbCreds['host'],
    $dbCreds['username'],
    $dbCreds['password'],
    $dbCreds['database']
);
?>
```

**CI/CD Integration (GitHub Actions):**
```yaml
# .github/workflows/build.yml
name: Build Firmware

on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Import Secrets from Vault
        uses: hashicorp/vault-action@v2
        with:
          url: https://vault.example.com:8200
          token: ${{ secrets.VAULT_TOKEN }}
          secrets: |
            secret/data/sensorwatch/certificates/firmware-signing private_key | SIGNING_KEY ;
            secret/data/sensorwatch/encryption file_encryption_key | ENCRYPTION_KEY
      
      - name: Build Firmware
        run: |
          echo "$SIGNING_KEY" > signing.key
          ./build.sh
```

#### 5. Secret Rotation Procedures

**Automated Rotation Script:**
```python
#!/usr/bin/env python3
# scripts/rotate-secrets.py

import hvac
import secrets
import string

def generate_password(length=32):
    """Generate cryptographically secure password"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def rotate_database_password(vault_client, db_connection):
    """Rotate database password"""
    # Generate new password
    new_password = generate_password()
    
    # Update database user password
    db_connection.execute(
        f"ALTER USER 'sensor_app_user' IDENTIFIED BY '{new_password}'"
    )
    
    # Update Vault
    vault_client.secrets.kv.v2.create_or_update_secret(
        path='sensorwatch/database',
        secret=dict(
            host='db5017073076.hosting-data.io',
            database='dbs13737298',
            username='sensor_app_user',
            password=new_password
        )
    )
    
    print("✓ Database password rotated successfully")

if __name__ == "__main__":
    # Initialize Vault client
    client = hvac.Client(
        url='https://vault.example.com:8200',
        token=os.environ['VAULT_TOKEN']
    )
    
    # Rotate secrets
    rotate_database_password(client, db_conn)
```

**Rotation Schedule:**
```bash
# Add to crontab for monthly rotation
0 2 1 * * /usr/local/bin/rotate-secrets.py >> /var/log/secret-rotation.log 2>&1
```

**Deliverables:**
- [ ] Vault server deployed and configured
- [ ] All secrets migrated to Vault
- [ ] Access policies defined
- [ ] Application integrations implemented
- [ ] Secret rotation procedures documented
- [ ] Backup and disaster recovery plan for Vault

---

### C3: Develop Security Architecture Standards
**Dependencies:** All teams need clear security guidelines

**How Discovered:**
Inconsistent security practices across codebase due to lack of documented standards.

**Required Document Structure:**

#### 1. Security Architecture Document

**Create:** `docs/security-architecture.md`

```markdown
# SensorWatch Security Architecture

## 1. Security Principles

### 1.1 Defense in Depth
Multiple layers of security controls:
- Network security (TLS encryption)
- Application security (authentication, input validation)
- Data security (encryption at rest)
- Infrastructure security (firewalls, monitoring)

### 1.2 Least Privilege
Every component operates with minimum necessary permissions:
- Database users: INSERT/SELECT only
- API keys: Device-specific
- File system: Whitelist-based access

### 1.3 Fail Securely
Default deny approach:
- Authentication required by default
- Unknown input rejected
- Errors logged, generic messages returned

### 1.4 Security by Design
Security built in from the start:
- Authentication required for all endpoints
- Input validation on all parameters
- Secure communication protocols

## 2. Authentication & Authorization

### 2.1 Web Interface
- **Method:** Session-based authentication
- **Token Format:** 64-character hex string (256-bit entropy)
- **Session Lifetime:** 1 hour with automatic renewal
- **Storage:** Server-side session map
- **Cookies:** HttpOnly, Secure, SameSite=Strict

### 2.2 API Authentication
- **Method:** Device-specific API keys
- **Key Format:** 64-character hex string (SHA-256 hash stored)
- **Rotation:** Every 90 days
- **Rate Limiting:** 1000 requests/hour per key

### 2.3 MQTT Authentication
- **Method:** Mutual TLS with client certificates
- **Certificate Validity:** 2 years
- **Username/Password:** Optional second factor
- **Authorization:** Topic-level ACLs

## 3. Encryption Standards

### 3.1 Transport Encryption
- **Protocol:** TLS 1.2 minimum (TLS 1.3 preferred)
- **Cipher Suites:** HIGH:!aNULL:!MD5
- **Certificate Validation:** Required
- **Certificate Pinning:** Recommended for MQTT

### 3.2 Data at Rest
- **Algorithm:** AES-256-GCM
- **Key Management:** Vault-managed keys
- **Sensitive Files:** wifi_config.json, mqtt_config.json
- **Backup Encryption:** Required

## 4. Input Validation

### 4.1 Validation Rules
All input must be validated against strict rules:
- **Sensor ID:** 16 hexadecimal characters
- **Reading Value:** Numeric, range -50 to 150
- **Timestamps:** ISO 8601 format, not future-dated
- **File Paths:** Whitelist-based, no traversal

### 4.2 Sanitization
- **SQL Injection:** Prepared statements mandatory
- **XSS Prevention:** htmlspecialchars() on all output
- **Path Traversal:** Remove "../" sequences
- **Command Injection:** No shell commands from user input

## 5. Logging & Monitoring

### 5.1 Security Event Logging
Log all security-relevant events:
- Authentication attempts (success/failure)
- Authorization failures
- Input validation failures
- API rate limit violations
- Certificate expiration warnings
- Configuration changes

### 5.2 Log Format
```json
{
  "timestamp": "2025-10-29T12:00:00Z",
  "event_type": "authentication_failure",
  "severity": "warning",
  "source_ip": "192.168.1.100",
  "user": "admin",
  "details": {...}
}
```

### 5.3 Log Retention
- Security logs: 90 days minimum
- Audit logs: 1 year
- Performance logs: 30 days

## 6. Incident Response

### 6.1 Severity Levels
- **Critical:** Active exploitation, data breach
- **High:** Vulnerable system exposed, authentication bypass
- **Medium:** Failed exploitation attempt, policy violation
- **Low:** Suspicious activity, configuration issue

### 6.2 Response Timeline
- **Critical:** Immediate response (< 1 hour)
- **High:** Same day response (< 4 hours)
- **Medium:** Next business day (< 24 hours)
- **Low:** Within one week

### 6.3 Escalation Path
1. Security Team Lead
2. Technical Lead
3. Engineering Manager
4. CTO/CISO

## 7. Vulnerability Management

### 7.1 Vulnerability Discovery
- Regular security audits (quarterly)
- Penetration testing (annually)
- Dependency scanning (automated)
- Bug bounty program

### 7.2 Remediation SLAs
- **Critical:** 7 days
- **High:** 30 days
- **Medium:** 90 days
- **Low:** Next major release

## 8. Secure Development

### 8.1 Code Review Requirements
All security-critical code requires:
- Peer review by security-trained developer
- Security team review for authentication/crypto
- Automated security scanning (SAST/DAST)

### 8.2 Testing Requirements
- Unit tests for all input validation
- Integration tests for authentication flows
- Security regression tests
- Penetration testing before production

## 9. Compliance

### 9.1 OWASP IoT Top 10
Map all findings to OWASP IoT Top 10 categories.
Track remediation progress.

### 9.2 GDPR Considerations
- Minimize data collection
- Encrypt personal data
- Implement data retention policies
- Provide data export capability

## 10. Security Metrics

Track and report monthly:
- Vulnerabilities by severity
- Mean time to remediation
- Authentication failure rate
- Certificate expiration dates
- Security test coverage
```

#### 2. Secure Coding Guidelines

**Create:** `docs/secure-coding-guidelines.md`

Focus on language-specific security best practices for:
- C++ (ESP32 firmware)
- PHP (backend API)
- JavaScript (frontend)
- SQL (database queries)

#### 3. Configuration Hardening Guides

**Create:** `docs/hardening-guides/`

Individual guides for:
- ESP32 firmware configuration
- Web server (Apache/Nginx)
- MySQL/MariaDB
- MQTT broker (Mosquitto)
- Network firewall rules

**Deliverables:**
- [ ] Security architecture document
- [ ] Secure coding guidelines
- [ ] Configuration hardening guides
- [ ] Security review checklists
- [ ] Threat model documentation

---

### C4: Implement Security Monitoring & SIEM
**Dependencies:** Security team needs visibility into security events

**How Discovered:**
No centralized security monitoring or alerting exists. Security events logged locally but not aggregated or analyzed.

**Required Actions:**

#### 1. SIEM Solution Selection

**Option A: ELK Stack (Elasticsearch, Logstash, Kibana)**

**Deployment:**
```yaml
# docker-compose.yml
version: '3.7'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.10.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=true
      - ELASTIC_PASSWORD=ChangeMeToSecurePassword
    volumes:
      - elasticsearch-data:/usr/share/elasticsearch/data
    ports:
      - 9200:9200

  logstash:
    image: docker.elastic.co/logstash/logstash:8.10.0
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline
      - ./logstash/config:/usr/share/logstash/config
    depends_on:
      - elasticsearch

  kibana:
    image: docker.elastic.co/kibana/kibana:8.10.0
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=elastic
      - ELASTICSEARCH_PASSWORD=ChangeMeToSecurePassword
    ports:
      - 5601:5601
    depends_on:
      - elasticsearch

volumes:
  elasticsearch-data:
```

#### 2. Log Aggregation Configuration

**Logstash Pipeline:**
```ruby
# logstash/pipeline/sensorwatch.conf

input {
  # Backend API logs
  file {
    path => "/var/log/php/sensorwatch_security.log"
    type => "security_event"
    codec => "json"
  }
  
  # Web server access logs
  file {
    path => "/var/log/apache2/access.log"
    type => "web_access"
  }
  
  # Firmware logs (via syslog)
  syslog {
    port => 514
    type => "firmware"
  }
  
  # Database audit logs
  file {
    path => "/var/log/mysql/audit.log"
    type => "database_audit"
    codec => "json"
  }
}

filter {
  if [type] == "security_event" {
    # Already JSON, just add metadata
    mutate {
      add_field => { "[@metadata][index]" => "sensorwatch-security-%{+YYYY.MM.dd}" }
    }
  }
  
  if [type] == "web_access" {
    grok {
      match => { "message" => "%{COMBINEDAPACHELOG}" }
    }
    
    date {
      match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
    }
    
    geoip {
      source => "clientip"
    }
  }
  
  # Detect authentication failures
  if [event_type] == "authentication_failure" {
    mutate {
      add_tag => [ "security_alert" ]
    }
  }
  
  # Detect SQL injection attempts
  if [type] == "web_access" and [request] =~ /(\%27|')|(--)|(\%23)|(#)/i {
    mutate {
      add_tag => [ "sql_injection_attempt", "security_alert" ]
    }
  }
  
  # Detect path traversal attempts
  if [type] == "web_access" and [request] =~ /\.\.\/|\.\.\\/ {
    mutate {
      add_tag => [ "path_traversal_attempt", "security_alert" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    user => "elastic"
    password => "ChangeMeToSecurePassword"
    index => "%{[@metadata][index]}"
  }
  
  # Send alerts to Slack
  if "security_alert" in [tags] {
    http {
      url => "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
      http_method => "post"
      format => "json"
      content_type => "application/json"
      message => '{
        "text": "Security Alert: %{event_type}",
        "attachments": [{
          "color": "danger",
          "fields": [
            {"title": "Source IP", "value": "%{source_ip}", "short": true},
            {"title": "Severity", "value": "%{severity}", "short": true},
            {"title": "Details", "value": "%{details}"}
          ]
        }]
      }'
    }
  }
}
```

#### 3. Security Dashboards

**Kibana Dashboard Configuration:**

Create dashboards for:

1. **Authentication Monitor:**
   - Failed login attempts by IP
   - Successful logins by user
   - Login attempts over time
   - Geographic distribution of access

2. **Attack Detection:**
   - SQL injection attempts
   - Path traversal attempts
   - XSS attempts
   - Rate limit violations

3. **API Monitoring:**
   - API requests by key
   - Response times
   - Error rates
   - Rate limit violations

4. **Certificate Status:**
   - Certificates expiring in 30 days
   - Certificate renewals
   - Revoked certificates

#### 4. Alerting Rules

**Create Alert Rules in Kibana:**

```json
{
  "name": "Multiple Failed Login Attempts",
  "schedule": {
    "interval": "5m"
  },
  "conditions": [{
    "query": {
      "bool": {
        "must": [
          {"match": {"event_type": "authentication_failure"}},
          {"range": {"@timestamp": {"gte": "now-5m"}}}
        ]
      }
    },
    "threshold": {
      "value": 5,
      "field": "source_ip"
    }
  }],
  "actions": [{
    "type": "slack",
    "message": "🚨 Multiple failed login attempts detected from {{source_ip}}"
  }, {
    "type": "email",
    "to": ["security@example.com"],
    "subject": "Security Alert: Brute Force Attempt"
  }]
}
```

**Additional Alert Rules:**
- Certificate expiring in < 30 days
- 5+ failed authentication attempts from same IP
- SQL injection pattern detected
- Unusual API usage pattern
- Database connection failures
- High error rate (> 10% requests)

#### 5. Incident Response Integration

**Automated Incident Creation:**
```python
#!/usr/bin/env python3
# scripts/create-incident.py

import requests
import json

def create_incident(alert_data):
    """Create incident in tracking system"""
    
    incident = {
        "title": f"Security Alert: {alert_data['event_type']}",
        "description": json.dumps(alert_data, indent=2),
        "severity": map_severity(alert_data.get('severity')),
        "tags": ["security", "automated"],
        "status": "open"
    }
    
    # Create in incident management system (e.g., Jira, PagerDuty)
    response = requests.post(
        "https://api.incident-system.com/incidents",
        headers={"Authorization": f"Bearer {API_TOKEN}"},
        json=incident
    )
    
    return response.json()

def map_severity(severity):
    mapping = {
        "critical": "P0",
        "high": "P1",
        "medium": "P2",
        "low": "P3"
    }
    return mapping.get(severity, "P3")
```

**Deliverables:**
- [ ] SIEM solution deployed
- [ ] Log aggregation configured
- [ ] Security dashboards created
- [ ] Alert rules defined
- [ ] Incident response integration
- [ ] Monitoring documentation

---

## HIGH PRIORITY TASKS

### H1: Conduct Threat Modeling Workshop

**Action:** Facilitate STRIDE analysis with all teams.

**Preparation:**
1. Review architecture diagrams
2. Identify all system components
3. Map data flows
4. Define trust boundaries

**Workshop Agenda:**
```
1. Architecture Overview (30 min)
   - System components
   - Data flows
   - Trust boundaries

2. STRIDE Analysis (2 hours)
   - Spoofing threats
   - Tampering threats
   - Repudiation threats
   - Information disclosure threats
   - Denial of service threats
   - Elevation of privilege threats

3. Risk Prioritization (30 min)
   - Likelihood assessment
   - Impact assessment
   - Risk scoring

4. Mitigation Planning (1 hour)
   - Control identification
   - Responsibility assignment
   - Timeline estimation
```

**Deliverable:** Updated threat model document with all identified threats and mitigation plans.

---

### H2: Establish Vulnerability Management Program

**Required Components:**

1. **Vulnerability Scanning:**
```bash
# Dependency scanning
npm audit
pip-audit
safety check

# Container scanning
trivy image sensorwatch-firmware:latest

# Code scanning (integrate with CI/CD)
semgrep --config=auto src/
```

2. **Vulnerability Tracking:**
```sql
CREATE TABLE vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(20) NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity ENUM('critical', 'high', 'medium', 'low'),
    cvss_score DECIMAL(3,1),
    affected_component VARCHAR(255),
    discovered_date DATE NOT NULL,
    remediation_deadline DATE,
    status ENUM('open', 'in_progress', 'resolved', 'wont_fix'),
    assigned_to VARCHAR(100),
    resolution_notes TEXT,
    INDEX idx_severity (severity),
    INDEX idx_status (status)
);
```

3. **Remediation SLAs:**
- Critical: 7 days
- High: 30 days
- Medium: 90 days
- Low: Next major release

**Deliverable:** Vulnerability management process document and tracking system.

---

### H3: Implement Security Testing Framework

**Required Testing:**

1. **Static Application Security Testing (SAST):**
```yaml
# .github/workflows/sast.yml
name: Security Scanning

on: [push, pull_request]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Run Semgrep
        run: |
          pip3 install semgrep
          semgrep --config=auto --error src/
      
      - name: Run Bandit (Python)
        run: |
          pip3 install bandit
          bandit -r src/ -f json -o bandit-report.json
      
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: sast-results
          path: |
            bandit-report.json
```

2. **Dynamic Application Security Testing (DAST):**
```bash
# Run OWASP ZAP against API
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t https://ecoforces.com/update_db.php \
  -r zap-report.html
```

3. **Dependency Scanning:**
```bash
# Check for known vulnerable dependencies
safety check --json
npm audit --json
```

**Deliverable:** Automated security testing pipeline integrated with CI/CD.

---

### H4: Create Security Baseline Configuration

**Configuration Management:**

1. **Version Control for Configurations:**
```bash
# Git repository structure
configs/
├── firmware/
│   ├── security-config.h
│   └── platformio.ini
├── backend/
│   ├── php.ini
│   └── apache.conf
├── database/
│   └── mysql-secure.cnf
├── mqtt/
│   └── mosquitto-secure.conf
└── network/
    └── firewall-rules.sh
```

2. **Configuration Validation:**
```python
#!/usr/bin/env python3
# scripts/validate-config.py

import re

def validate_php_config(config_file):
    """Validate PHP security settings"""
    with open(config_file) as f:
        content = f.read()
    
    required_settings = {
        'display_errors': 'Off',
        'expose_php': 'Off',
        'allow_url_fopen': 'Off',
        'allow_url_include': 'Off'
    }
    
    for setting, expected_value in required_settings.items():
        pattern = f"{setting}\\s*=\\s*{expected_value}"
        if not re.search(pattern, content, re.IGNORECASE):
            print(f"❌ {setting} not set to {expected_value}")
            return False
    
    print("✓ PHP configuration validated")
    return True
```

**Deliverable:** Baseline configuration repository with validation scripts.

---

### H5: Implement Access Control Framework

**Role-Based Access Control (RBAC):**

1. **Define Roles:**
```sql
CREATE TABLE roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    resource VARCHAR(100) NOT NULL,
    action ENUM('read', 'write', 'delete', 'execute'),
    UNIQUE KEY resource_action (resource, action)
);

CREATE TABLE role_permissions (
    role_id INT NOT NULL,
    permission_id INT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (permission_id) REFERENCES permissions(id)
);

CREATE TABLE user_roles (
    user_id INT NOT NULL,
    role_id INT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

-- Define standard roles
INSERT INTO roles (name, description) VALUES
('admin', 'Full system access'),
('operator', 'Read and basic operations'),
('viewer', 'Read-only access'),
('device', 'Device data submission');
```

2. **Permission Enforcement:**
```php
<?php
class AccessControl {
    private $userRoles;
    
    public function __construct($userId) {
        $this->userRoles = $this->loadUserRoles($userId);
    }
    
    public function hasPermission($resource, $action) {
        foreach ($this->userRoles as $role) {
            $permissions = $this->loadRolePermissions($role);
            
            foreach ($permissions as $perm) {
                if ($perm['resource'] === $resource && 
                    $perm['action'] === $action) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    public function requirePermission($resource, $action) {
        if (!$this->hasPermission($resource, $action)) {
            http_response_code(403);
            die(json_encode(["error" => "Insufficient permissions"]));
        }
    }
}

// Usage
$ac = new AccessControl($_SESSION['user_id']);
$ac->requirePermission('sensor_data', 'write');
?>
```

**Deliverable:** RBAC system with role definitions and enforcement mechanism.

---

### H6: Establish Incident Response Plan

**Create:** `docs/incident-response-plan.md`

**Contents:**

1. **Incident Classification:**
   - Critical: Data breach, active exploitation
   - High: Vulnerable system exposed
   - Medium: Failed exploitation attempt
   - Low: Suspicious activity

2. **Response Procedures:**
```markdown
## Critical Incident Response

### Immediate Actions (< 1 hour)
1. Isolate affected systems
2. Notify Security Team Lead
3. Activate incident response team
4. Begin evidence collection
5. Notify stakeholders

### Investigation Phase (1-4 hours)
1. Determine scope of compromise
2. Identify attack vector
3. Assess data exposure
4. Document all findings

### Containment Phase (4-8 hours)
1. Block attack vector
2. Revoke compromised credentials
3. Apply emergency patches
4. Monitor for continued activity

### Recovery Phase (8-24 hours)
1. Restore from clean backups
2. Deploy permanent fixes
3. Verify system integrity
4. Resume normal operations

### Post-Incident Phase (1-7 days)
1. Root cause analysis
2. Lessons learned documentation
3. Process improvements
4. Security awareness training
```

3. **Communication Templates:**
```markdown
## Internal Notification Template

Subject: Security Incident Alert - [Severity]

A security incident has been detected:
- Incident ID: [ID]
- Severity: [Critical/High/Medium/Low]
- Affected Systems: [List]
- Discovery Time: [Timestamp]
- Current Status: [Status]

Immediate actions taken:
- [Action 1]
- [Action 2]

Next steps:
- [Step 1]
- [Step 2]

Contact: [Security Team Lead] for questions
```

4. **Contact Information:**
   - Security Team Lead: [contact]
   - Technical Lead: [contact]
   - Engineering Manager: [contact]
   - External Security Consultant: [contact]

**Deliverable:** Comprehensive incident response plan with procedures and contacts.

---

## MEDIUM PRIORITY TASKS

### M1: Implement Security Awareness Training

**Training Program:**

1. **Secure Coding Training:**
   - OWASP Top 10
   - Common Vulnerabilities
   - Secure Design Patterns
   - Code Review Best Practices

2. **Security Champions Program:**
   - Identify security champions in each team
   - Advanced security training
   - Regular knowledge sharing sessions

3. **Phishing Awareness:**
   - Simulated phishing campaigns
   - Reporting procedures
   - Social engineering awareness

**Deliverable:** Training materials and security champions program.

---

### M2: Establish Compliance Framework

**Compliance Mapping:**

1. **OWASP IoT Top 10:**
   - Map all vulnerabilities
   - Track remediation status
   - Quarterly assessments

2. **GDPR Compliance:**
   - Data inventory
   - Privacy impact assessments
   - Data retention policies
   - Right to erasure procedures

3. **Industry Standards:**
   - NIST Cybersecurity Framework
   - ISO 27001 (if required)

**Deliverable:** Compliance documentation and assessment reports.

---

### M3: Implement Network Segmentation

**Network Architecture:**

```
┌─────────────────────────────────────┐
│         Internet                    │
└──────────────┬──────────────────────┘
               │
         ┌─────▼─────┐
         │  Firewall │
         └─────┬─────┘
               │
    ┌──────────┼──────────┐
    │          │          │
┌───▼────┐ ┌──▼────┐ ┌──▼────┐
│  DMZ   │ │ App   │ │ IoT   │
│ VLAN10 │ │ VLAN20│ │ VLAN30│
└────────┘ └───────┘ └───────┘
```

**Firewall Rules:**
```bash
# VLAN 30 (IoT) - Outbound only
iptables -A FORWARD -i vlan30 -o vlan20 -m state --state NEW -j DROP
iptables -A FORWARD -i vlan30 -o vlan10 -m state --state NEW -j DROP

# VLAN 20 (App) - Can initiate to IoT and DMZ
iptables -A FORWARD -i vlan20 -o vlan30 -p tcp --dport 443 -j ACCEPT
iptables -A FORWARD -i vlan20 -o vlan10 -p tcp --dport 443 -j ACCEPT

# DMZ - Inbound from Internet, outbound to App only
iptables -A FORWARD -i vlan10 -o vlan20 -j ACCEPT
```

**Deliverable:** Network segmentation plan and firewall configuration.

---

## TESTING REQUIREMENTS

### Security Test Cases

1. **Authentication Testing:**
   - [ ] Brute force protection
   - [ ] Session timeout enforcement
   - [ ] Password complexity requirements
   - [ ] Multi-factor authentication (if implemented)

2. **Authorization Testing:**
   - [ ] Privilege escalation attempts
   - [ ] Direct object reference manipulation
   - [ ] Role permission enforcement

3. **Input Validation Testing:**
   - [ ] SQL injection attempts
   - [ ] XSS payloads
   - [ ] Path traversal attempts
   - [ ] Command injection attempts

4. **Cryptography Testing:**
   - [ ] TLS configuration validation
   - [ ] Certificate validation
   - [ ] Encryption algorithm verification

5. **Session Management:**
   - [ ] Session fixation attempts
   - [ ] Session hijacking attempts
   - [ ] Cookie security attributes

---

## DEPENDENCIES

### Deliverables to Other Teams

**To Firmware Team:**
- [ ] Root CA certificate
- [ ] Device certificate signing process
- [ ] Firmware signing certificate and private key
- [ ] MQTT broker CA certificate
- [ ] Encryption key management guidelines

**To Backend Team:**
- [ ] SSL certificate for API domain
- [ ] Vault integration documentation
- [ ] Secret rotation procedures
- [ ] Security monitoring integration

**To Database Team:**
- [ ] Database encryption guidelines
- [ ] Audit logging requirements
- [ ] Backup encryption procedures

**To Frontend Team:**
- [ ] CSP policy requirements
- [ ] Security headers specification
- [ ] Authentication token format

---

## PROJECT COORDINATION

### Weekly Security Sync
**When:** Wednesdays 2PM  
**Attendees:** Security team + team leads

**Agenda:**
1. Remediation progress review
2. Blocker discussion
3. Upcoming deliverables
4. Security incidents review

### Documentation Repository
**Location:** `docs/security/`

**Structure:**
```
docs/security/
├── architecture/
│   ├── security-architecture.md
│   ├── threat-model.md
│   └── trust-boundaries.md
├── procedures/
│   ├── incident-response-plan.md
│   ├── certificate-management.md
│   └── secret-rotation.md
├── guidelines/
│   ├── secure-coding-guidelines.md
│   ├── code-review-checklist.md
│   └── security-testing.md
├── compliance/
│   ├── owasp-iot-mapping.md
│   └── gdpr-compliance.md
└── operations/
    ├── monitoring-setup.md
    ├── alert-runbooks.md
    └── backup-procedures.md
```

---

## SUCCESS CRITERIA

- [ ] PKI infrastructure operational
- [ ] Secrets management system deployed
- [ ] All secrets migrated from code to Vault
- [ ] Security monitoring collecting logs from all systems
- [ ] Security dashboards created and monitored
- [ ] Incident response procedures tested
- [ ] Security awareness training completed
- [ ] All teams have clear security guidelines
- [ ] Vulnerability management process operational
- [ ] Security testing integrated into CI/CD

---

**Report Generated:** Security Audit Team  
**Document Version:** 1.0  
**Last Updated:** December 16, 2025

---

# DATABASE TEAM - Security Remediation Tasks

**Project:** SensorWatch IoT Security Hardening  
**Component:** MySQL/MariaDB Database  
**Audit Date:** October 29, 2025  
**Priority:** CRITICAL - Foundation for Data Security

---

## CRITICAL PRIORITY

### C1: Implement Principle of Least Privilege
**CVSS Score:** Related to CRITICAL-002 (9.8)

**How Discovered:**
Database user credentials found in PHP code suggest application has excessive permissions. Testing confirmed current user likely has administrative privileges.

**Current Issue:**
Application user (`dbu5607697`) may have:
- Full database access (SELECT, INSERT, UPDATE, DELETE)
- Schema modification rights (CREATE, ALTER, DROP)
- Administrative privileges
- Access to other databases

**Security Impact:**
If application is compromised via SQL injection:
- Attacker can modify database schema
- All data can be deleted or corrupted
- Other databases may be accessible
- Database users can be created/modified

**Required Actions:**

#### 1. Create Limited Application User

```sql
-- Connect as database administrator
mysql -u root -p

-- Create new limited user for application
CREATE USER 'sensor_app'@'%' 
IDENTIFIED BY '<SECURE_RANDOM_PASSWORD_HERE>';

-- Grant ONLY necessary permissions
GRANT INSERT, SELECT ON dbs13737298.sensor_readings 
TO 'sensor_app'@'%';

-- Verify permissions
SHOW GRANTS FOR 'sensor_app'@'%';

-- Expected output:
-- GRANT INSERT, SELECT ON `dbs13737298`.`sensor_readings` TO `sensor_app`@`%`

FLUSH PRIVILEGES;
```

#### 2. Create Read-Only User for Reporting

```sql
-- Create read-only user for dashboards/reports
CREATE USER 'sensor_readonly'@'%'
IDENTIFIED BY '<SECURE_RANDOM_PASSWORD_HERE>';

-- Grant SELECT only
GRANT SELECT ON dbs13737298.sensor_readings 
TO 'sensor_readonly'@'%';

FLUSH PRIVILEGES;
```

#### 3. Create Backup User

```sql
-- Create user for automated backups
CREATE USER 'sensor_backup'@'localhost'
IDENTIFIED BY '<SECURE_RANDOM_PASSWORD_HERE>';

-- Grant necessary backup privileges
GRANT SELECT, LOCK TABLES, SHOW VIEW, EVENT, TRIGGER 
ON dbs13737298.* 
TO 'sensor_backup'@'localhost';

FLUSH PRIVILEGES;
```

#### 4. Revoke Old User Permissions

```sql
-- After verifying application works with new user:

-- Revoke all privileges from old user
REVOKE ALL PRIVILEGES, GRANT OPTION 
FROM 'dbu5607697'@'%';

-- Verify no permissions remain
SHOW GRANTS FOR 'dbu5607697'@'%';

-- If user is no longer needed, drop it
DROP USER 'dbu5607697'@'%';

FLUSH PRIVILEGES;
```

#### 5. Restrict User Access by Host

For production, restrict to specific application server IP:

```sql
-- Create user that can only connect from app server
CREATE USER 'sensor_app'@'192.168.1.50'
IDENTIFIED BY '<SECURE_RANDOM_PASSWORD_HERE>';

GRANT INSERT, SELECT ON dbs13737298.sensor_readings 
TO 'sensor_app'@'192.168.1.50';

-- Remove wildcard access
DROP USER 'sensor_app'@'%';

FLUSH PRIVILEGES;
```

#### 6. Verification Script

```bash
#!/bin/bash
# scripts/verify-db-permissions.sh

echo "=== Database Permission Audit ==="

# Test application user permissions
mysql -u sensor_app -p <<EOF
-- Should succeed
SELECT COUNT(*) FROM dbs13737298.sensor_readings;
INSERT INTO dbs13737298.sensor_readings (sensor_id, reading_value) 
VALUES ('TEST', 0);

-- Should fail
UPDATE dbs13737298.sensor_readings SET reading_value = 999 WHERE sensor_id = 'TEST';
DELETE FROM dbs13737298.sensor_readings WHERE sensor_id = 'TEST';
CREATE TABLE dbs13737298.test_table (id INT);
DROP TABLE dbs13737298.sensor_readings;
EOF

echo "✓ Permission verification complete"
echo "  - SELECT: Should succeed"
echo "  - INSERT: Should succeed"  
echo "  - UPDATE: Should fail"
echo "  - DELETE: Should fail"
echo "  - CREATE TABLE: Should fail"
echo "  - DROP TABLE: Should fail"
```

**Deliverables:**
- [ ] New limited database users created
- [ ] Application updated to use new credentials
- [ ] Old user permissions revoked
- [ ] Permission verification completed
- [ ] Documentation of user roles and permissions

**Dependencies:** 
- Backend team (update database credentials)
- Security team (store new credentials in Vault)

---

## HIGH PRIORITY

### H1: Enable Database Connection Encryption
**How Discovered:**
Network traffic analysis shows database connections use plaintext protocol.

**Security Impact:**
- Database credentials transmitted in cleartext
- Query contents visible to network eavesdroppers
- Result sets exposed during transmission

**Required Actions:**

#### 1. Generate SSL Certificates

```bash
# Create certificate directory
mkdir -p /etc/mysql/ssl
cd /etc/mysql/ssl

# Generate CA certificate
openssl genrsa 2048 > ca-key.pem
openssl req -new -x509 -nodes -days 3650 \
  -key ca-key.pem -out ca-cert.pem \
  -subj "/C=US/ST=State/O=WinWinLabs/CN=MySQL_CA"

# Generate server certificate
openssl req -newkey rsa:2048 -days 3650 -nodes \
  -keyout server-key.pem -out server-req.pem \
  -subj "/C=US/ST=State/O=WinWinLabs/CN=MySQL_Server"

openssl rsa -in server-key.pem -out server-key.pem

openssl x509 -req -in server-req.pem -days 3650 \
  -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 \
  -out server-cert.pem

# Generate client certificate (optional for mutual TLS)
openssl req -newkey rsa:2048 -days 3650 -nodes \
  -keyout client-key.pem -out client-req.pem \
  -subj "/C=US/ST=State/O=WinWinLabs/CN=MySQL_Client"

openssl rsa -in client-key.pem -out client-key.pem

openssl x509 -req -in client-req.pem -days 3650 \
  -CA ca-cert.pem -CAkey ca-key.pem -set_serial 02 \
  -out client-cert.pem

# Set permissions
chmod 600 *-key.pem
chmod 644 *-cert.pem ca-cert.pem
chown mysql:mysql *
```

#### 2. Configure MySQL for TLS

```ini
# /etc/mysql/mysql.conf.d/mysqld.cnf

[mysqld]
# SSL Configuration
ssl-ca=/etc/mysql/ssl/ca-cert.pem
ssl-cert=/etc/mysql/ssl/server-cert.pem
ssl-key=/etc/mysql/ssl/server-key.pem

# Require SSL for all connections
require_secure_transport=ON

# TLS version configuration
tls_version=TLSv1.2,TLSv1.3

# SSL cipher configuration
ssl_cipher=ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384
```

#### 3. Restart MySQL

```bash
systemctl restart mysql

# Verify SSL is enabled
mysql -u root -p -e "SHOW VARIABLES LIKE '%ssl%';"

# Expected output should show:
# have_ssl = YES
# ssl_ca = /etc/mysql/ssl/ca-cert.pem
# ssl_cert = /etc/mysql/ssl/server-cert.pem
# ssl_key = /etc/mysql/ssl/server-key.pem
```

#### 4. Update User Requirements

```sql
-- Require SSL for application user
ALTER USER 'sensor_app'@'%' 
REQUIRE SSL;

-- Verify
SHOW CREATE USER 'sensor_app'@'%';

FLUSH PRIVILEGES;
```

#### 5. Update Client Configuration

**PHP Client (for Backend):**
```php
<?php
$mysqli = new mysqli();
$mysqli->options(MYSQLI_OPT_SSL_VERIFY_SERVER_CERT, true);
$mysqli->ssl_set(
    NULL,  // key
    NULL,  // cert  
    '/path/to/ca-cert.pem',  // CA
    NULL,  // capath
    NULL   // cipher
);

$mysqli->real_connect(
    $host,
    $username,
    $password,
    $database,
    3306,
    NULL,
    MYSQLI_CLIENT_SSL
);

if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}

// Verify SSL is being used
$result = $mysqli->query("SHOW STATUS LIKE 'Ssl_cipher'");
$row = $result->fetch_assoc();
if (empty($row['Value'])) {
    die("SSL not enabled!");
}

echo "✓ Connected with SSL cipher: " . $row['Value'];
?>
```

#### 6. Verification

```bash
# Test SSL connection
mysql -u sensor_app -p \
  --ssl-ca=/etc/mysql/ssl/ca-cert.pem \
  --ssl-mode=REQUIRED \
  -e "SHOW STATUS LIKE 'Ssl_cipher';"

# Should show the cipher being used
# If empty, SSL is not working
```

**Deliverables:**
- [ ] SSL certificates generated
- [ ] MySQL configured for TLS
- [ ] User accounts require SSL
- [ ] Client applications updated
- [ ] Connection encryption verified

**Dependencies:** Security team (certificate management)

---

### H2: Implement Database Auditing
**How Discovered:**
No audit logs exist for database access or modifications.

**Security Impact:**
- Cannot detect unauthorized access
- Cannot trace data modifications
- No forensic evidence for incidents
- Compliance requirement failures

**Required Actions:**

#### 1. Enable MariaDB Audit Plugin

```sql
-- Install audit plugin
INSTALL SONAME 'server_audit';

-- Configure audit settings
SET GLOBAL server_audit_logging = ON;
SET GLOBAL server_audit_events = 'CONNECT,QUERY,TABLE';
SET GLOBAL server_audit_file_path = '/var/log/mysql/audit.log';
SET GLOBAL server_audit_file_rotate_size = 1000000;  -- 1MB
SET GLOBAL server_audit_file_rotations = 9;

-- Verify plugin is active
SHOW PLUGINS;
SHOW GLOBAL VARIABLES LIKE 'server_audit%';
```

#### 2. Make Audit Settings Persistent

```ini
# /etc/mysql/mysql.conf.d/mysqld.cnf

[mysqld]
# Audit Plugin Configuration
plugin-load-add=server_audit.so
server_audit_logging=ON
server_audit_events=CONNECT,QUERY,TABLE
server_audit_file_path=/var/log/mysql/audit.log
server_audit_file_rotate_size=1000000
server_audit_file_rotations=9
server_audit_incl_users=sensor_app,sensor_readonly

# Exclude system queries (optional)
server_audit_excl_users=debian-sys-maint,mysql
```

#### 3. Configure Log Rotation

```bash
# /etc/logrotate.d/mysql-audit

/var/log/mysql/audit.log {
    daily
    rotate 90
    missingok
    notifempty
    compress
    delaycompress
    dateext
    dateformat -%Y%m%d-%s
    create 640 mysql adm
    sharedscripts
    postrotate
        if [ -f /var/run/mysqld/mysqld.pid ]; then
            mysql -e "SET GLOBAL server_audit_file_rotate_now = ON;" 2>/dev/null || true
        fi
    endscript
}
```

#### 4. Audit Log Analysis Script

```python
#!/usr/bin/env python3
# scripts/analyze-audit-log.py

import re
import sys
from collections import Counter
from datetime import datetime

def parse_audit_log(log_file):
    """Parse MySQL audit log and generate security report"""
    
    failed_logins = []
    sql_errors = []
    suspicious_queries = []
    user_activity = Counter()
    
    with open(log_file, 'r') as f:
        for line in f:
            # Parse log line (format varies by plugin version)
            if 'ACCESS DENIED' in line or 'FAILED_CONNECT' in line:
                failed_logins.append(line.strip())
            
            if 'ERROR' in line:
                sql_errors.append(line.strip())
            
            # Detect suspicious patterns
            suspicious_patterns = [
                r"UNION\s+SELECT",
                r"DROP\s+TABLE",
                r"DELETE\s+FROM.*WHERE\s+1\s*=\s*1",
                r";\s*--",
                r"'\s*OR\s+'.*'='",
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    suspicious_queries.append(line.strip())
            
            # Track user activity
            user_match = re.search(r"USER:\s*'([^']+)'", line)
            if user_match:
                user_activity[user_match.group(1)] += 1
    
    # Generate report
    print("=== MySQL Audit Log Analysis ===\n")
    
    print(f"Failed Login Attempts: {len(failed_logins)}")
    if failed_logins:
        print("Recent failures:")
        for failure in failed_logins[-5:]:
            print(f"  {failure}")
    print()
    
    print(f"SQL Errors: {len(sql_errors)}")
    if sql_errors:
        print("Recent errors:")
        for error in sql_errors[-5:]:
            print(f"  {error}")
    print()
    
    print(f"Suspicious Queries: {len(suspicious_queries)}")
    if suspicious_queries:
        print("⚠️  Possible SQL injection attempts:")
        for query in suspicious_queries:
            print(f"  {query}")
    print()
    
    print("User Activity:")
    for user, count in user_activity.most_common(10):
        print(f"  {user}: {count} queries")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <audit_log_file>")
        sys.exit(1)
    
    parse_audit_log(sys.argv[1])
```

#### 5. Set Up Alerting

```bash
#!/bin/bash
# scripts/audit-alert.sh
# Run this script via cron every 5 minutes

AUDIT_LOG="/var/log/mysql/audit.log"
ALERT_FILE="/tmp/mysql-audit-alert.txt"

# Check for failed login attempts in last 5 minutes
FAILED_LOGINS=$(tail -n 10000 "$AUDIT_LOG" | \
  grep -c "ACCESS DENIED\|FAILED_CONNECT")

if [ "$FAILED_LOGINS" -gt 10 ]; then
    echo "⚠️  WARNING: $FAILED_LOGINS failed login attempts detected" \
      | mail -s "MySQL Security Alert" security@example.com
fi

# Check for DROP TABLE commands (should never happen)
DROP_COMMANDS=$(tail -n 10000 "$AUDIT_LOG" | grep -c "DROP TABLE")

if [ "$DROP_COMMANDS" -gt 0 ]; then
    echo "🚨 CRITICAL: DROP TABLE command detected in audit log!" \
      | mail -s "MySQL CRITICAL Alert" security@example.com
fi
```

**Deliverables:**
- [ ] Audit plugin installed and configured
- [ ] Log rotation configured
- [ ] Audit analysis scripts created
- [ ] Alerting for suspicious activity
- [ ] Regular audit log reviews scheduled

---

## MEDIUM PRIORITY

### M1: Optimize Database Performance with Security
**Action:** Add indexes while maintaining security.

```sql
-- Analyze current query patterns
SELECT * FROM INFORMATION_SCHEMA.PROCESSLIST 
WHERE COMMAND != 'Sleep' 
ORDER BY TIME DESC;

-- Add indexes for common queries
CREATE INDEX idx_sensor_timestamp 
ON sensor_readings(sensor_id, timestamp);

CREATE INDEX idx_timestamp 
ON sensor_readings(timestamp);

-- Analyze query performance
EXPLAIN SELECT * FROM sensor_readings 
WHERE sensor_id = 'ABC123DEF4567890' 
AND timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR);

-- Update table statistics
ANALYZE TABLE sensor_readings;
OPTIMIZE TABLE sensor_readings;
```

---

### M2: Implement Automated Backups with Encryption
**Action:** Set up secure automated backup system.

```bash
#!/bin/bash
# scripts/backup-database.sh

BACKUP_DIR="/backups/mysql"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="dbs13737298"
BACKUP_FILE="${BACKUP_DIR}/backup_${DB_NAME}_${DATE}.sql.gz.enc"
ENCRYPTION_KEY="/secure/backup-encryption.key"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Dump database
mysqldump \
  --single-transaction \
  --routines \
  --triggers \
  --events \
  -u sensor_backup \
  -p"$BACKUP_PASSWORD" \
  "$DB_NAME" | \
  gzip | \
  openssl enc -aes-256-cbc -salt \
    -pass file:"$ENCRYPTION_KEY" \
    -out "$BACKUP_FILE"

if [ $? -eq 0 ]; then
    echo "✓ Backup created: $BACKUP_FILE"
    
    # Upload to remote storage (optional)
    # aws s3 cp "$BACKUP_FILE" s3://backups/sensorwatch/
    
    # Verify backup integrity
    gunzip < "$BACKUP_FILE" | \
      openssl enc -d -aes-256-cbc -pass file:"$ENCRYPTION_KEY" | \
      head -n 1 > /dev/null
    
    if [ $? -eq 0 ]; then
        echo "✓ Backup integrity verified"
    else
        echo "❌ Backup verification failed!"
        exit 1
    fi
    
    # Clean up old backups (keep last 30 days)
    find "$BACKUP_DIR" -name "backup_*.sql.gz.enc" \
      -mtime +30 -delete
    
else
    echo "❌ Backup failed!"
    exit 1
fi
```

**Cron Configuration:**
```bash
# Add to crontab
# Daily backup at 2 AM
0 2 * * * /usr/local/bin/backup-database.sh >> /var/log/mysql-backup.log 2>&1
```

---

### M3: Implement Connection Pooling and Limits
**Action:** Prevent resource exhaustion.

```ini
# /etc/mysql/mysql.conf.d/mysqld.cnf

[mysqld]
# Connection limits
max_connections=100
max_connect_errors=10
max_user_connections=50

# Connection timeouts
wait_timeout=600
interactive_timeout=600
connect_timeout=10

# Thread configuration
thread_cache_size=8

# Buffer pool (adjust based on available RAM)
innodb_buffer_pool_size=1G
innodb_log_file_size=256M
```

---

## TESTING REQUIREMENTS

### Security Tests

1. **Permission Verification:**
```bash
# Test limited user cannot perform unauthorized actions
mysql -u sensor_app -p -e "DROP TABLE sensor_readings;" 
# Expected: ERROR 1142 (42000): DROP command denied

mysql -u sensor_app -p -e "CREATE USER 'hacker'@'%';"
# Expected: ERROR 1227 (42000): Access denied
```

2. **SSL Enforcement:**
```bash
# Test that non-SSL connections are rejected
mysql -u sensor_app -p --skip-ssl
# Expected: ERROR 1045 (28000): Access denied (or connection refused)
```

3. **Audit Logging:**
```bash
# Perform test query
mysql -u sensor_app -p -e "SELECT COUNT(*) FROM sensor_readings;"

# Verify it's logged
grep "sensor_app" /var/log/mysql/audit.log
# Expected: Should show the SELECT query
```

---

## DEPENDENCIES

### From Security Team
- [ ] Certificate management for TLS
- [ ] Backup encryption keys
- [ ] Secrets management (Vault) integration

### From Backend Team
- [ ] Application testing with new database users
- [ ] Connection string updates
- [ ] Error handling for SSL requirements

---

## DEPLOYMENT CHECKLIST

- [ ] Create new limited database users
- [ ] Test application with new users
- [ ] Update credentials in Vault
- [ ] Update application configuration
- [ ] Revoke old user permissions
- [ ] Enable TLS for connections
- [ ] Test TLS connectivity
- [ ] Enable audit logging
- [ ] Configure backup system
- [ ] Verify all security controls
- [ ] Document changes

---

**Report Generated:** Security Audit Team  
**Document Version:** 1.0  
**Last Updated:** December 16, 2025

---

# FRONTEND TEAM - Security Remediation Tasks

**Project:** SensorWatch IoT Security Hardening  
**Component:** Web Interface (`src/main.cpp` HTML/JavaScript sections)  
**Audit Date:** October 29, 2025  
**Priority:** CRITICAL - User-Facing Security

---

## CRITICAL PRIORITY

### C1: Remove Client-Side Authentication
**CVSS Score:** Related to CRITICAL-003 (9.1)

**How Discovered:**
Source code review revealed OTA login page uses JavaScript to validate credentials:

```javascript
function check(form) {
  if (form.userid.value == 'admin' && form.pwd.value == 'admin') {
    window.location.href = '/serverIndex';
  } else {
    alert('Error: Incorrect Username or Password');
  }
}
```

**Security Impact:**
- Credentials visible in client-side source code
- Authentication completely bypassed by accessing `/serverIndex` directly
- No server-side validation
- No session management

**Required Fix:**
Implement proper server-side authentication flow.

#### 1. Updated Login Form (HTML)

```html
<!-- Login Page -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SensorWatch - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
        }
        
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: 500;
        }
        
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        button {
            width: 100%;
            padding: 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s;
        }
        
        button:hover {
            background: #5568d3;
        }
        
        button:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        
        .error-message {
            background: #fee;
            color: #c33;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            display: none;
        }
        
        .error-message.show {
            display: block;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>🔒 SensorWatch</h1>
        
        <div id="error-message" class="error-message"></div>
        
        <form id="login-form">
            <div class="form-group">
                <label for="username">Username</label>
                <input 
                    type="text" 
                    id="username" 
                    name="username" 
                    required 
                    autocomplete="username"
                    maxlength="50"
                >
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input 
                    type="password" 
                    id="password" 
                    name="password" 
                    required 
                    autocomplete="current-password"
                    maxlength="100"
                >
            </div>
            
            <button type="submit" id="login-button">
                Sign In
            </button>
        </form>
    </div>
    
    <script>
        const form = document.getElementById('login-form');
        const errorDiv = document.getElementById('error-message');
        const loginButton = document.getElementById('login-button');
        
        // Track failed attempts for rate limiting
        let failedAttempts = 0;
        let lockoutUntil = 0;
        
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            // Check if locked out
            if (Date.now() < lockoutUntil) {
                const remainingSeconds = Math.ceil((lockoutUntil - Date.now()) / 1000);
                showError(`Too many failed attempts. Try again in ${remainingSeconds} seconds.`);
                return;
            }
            
            // Disable form during submission
            loginButton.disabled = true;
            loginButton.textContent = 'Signing in...';
            errorDiv.classList.remove('show');
            
            const formData = new FormData(form);
            const username = formData.get('username');
            const password = formData.get('password');
            
            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username, password })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    
                    // Store session token securely
                    sessionStorage.setItem('session_token', data.token);
                    
                    // Redirect to dashboard
                    window.location.href = '/dashboard';
                } else {
                    failedAttempts++;
                    
                    // Implement exponential backoff
                    if (failedAttempts >= 3) {
                        const lockoutDuration = Math.pow(2, failedAttempts - 3) * 5000; // 5s, 10s, 20s, etc.
                        lockoutUntil = Date.now() + lockoutDuration;
                        showError(`Too many failed attempts. Locked out for ${lockoutDuration / 1000} seconds.`);
                    } else {
                        const data = await response.json();
                        showError(data.error || 'Invalid username or password');
                    }
                }
            } catch (error) {
                console.error('Login error:', error);
                showError('Connection error. Please try again.');
            } finally {
                loginButton.disabled = false;
                loginButton.textContent = 'Sign In';
            }
        });
        
        function showError(message) {
            errorDiv.textContent = message;
            errorDiv.classList.add('show');
            
            // Clear error after 5 seconds
            setTimeout(() => {
                errorDiv.classList.remove('show');
            }, 5000);
        }
    </script>
</body>
</html>
```

#### 2. Session Management (JavaScript)

```javascript
// session-manager.js

class SessionManager {
    constructor() {
        this.tokenKey = 'session_token';
        this.checkInterval = 60000; // Check every minute
        this.warningTime = 300000; // Warn 5 minutes before expiry
        
        this.startSessionMonitoring();
    }
    
    getToken() {
        return sessionStorage.getItem(this.tokenKey);
    }
    
    setToken(token) {
        sessionStorage.setItem(this.tokenKey);
        this.startSessionMonitoring();
    }
    
    clearToken() {
        sessionStorage.removeItem(this.tokenKey);
    }
    
    async validateSession() {
        const token = this.getToken();
        
        if (!token) {
            this.redirectToLogin();
            return false;
        }
        
        try {
            const response = await fetch('/api/validate-session', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (!response.ok) {
                this.clearToken();
                this.redirectToLogin();
                return false;
            }
            
            const data = await response.json();
            
            // Check if session is expiring soon
            if (data.expires_in < this.warningTime) {
                this.showSessionWarning(data.expires_in);
            }
            
            return true;
            
        } catch (error) {
            console.error('Session validation error:', error);
            return false;
        }
    }
    
    startSessionMonitoring() {
        // Clear any existing interval
        if (this.monitorInterval) {
            clearInterval(this.monitorInterval);
        }
        
        // Check session periodically
        this.monitorInterval = setInterval(() => {
            this.validateSession();
        }, this.checkInterval);
    }
    
    showSessionWarning(timeRemaining) {
        const minutes = Math.ceil(timeRemaining / 60000);
        
        // Create warning modal if it doesn't exist
        if (!document.getElementById('session-warning')) {
            const modal = document.createElement('div');
            modal.id = 'session-warning';
            modal.innerHTML = `
