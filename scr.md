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
