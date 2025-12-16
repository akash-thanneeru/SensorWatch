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
