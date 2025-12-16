# FIRMWARE TEAM - Security Remediation Tasks

**Project:** SensorWatch IoT Security Hardening  
**Component:** ESP32 Firmware (`src/main.cpp`)  
**Audit Date:** December 16, 2025
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
