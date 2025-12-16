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
            modal.innerHTML = ``
                <div style="position: fixed; top: 20px; right: 20px; background: #fff3cd; 
                            border: 2px solid #ffc107; border-radius: 8px; padding: 20px; 
                            max-width: 400px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); z-index: 10000;">
                    <h3 style="margin: 0 0 10px 0; color: #856404;">⏰ Session Expiring Soon</h3>
                    <p style="margin: 0 0 15px 0; color: #856404;">
                        Your session will expire in ${minutes} minute${minutes > 1 ? 's' : ''}.
                    </p>
                    <button onclick="sessionManager.extendSession()" 
                            style="width: 100%; padding: 10px; background: #ffc107; 
                                   border: none; border-radius: 5px; cursor: pointer; 
                                   font-weight: 600; color: #000;">
                        Extend Session
                    </button>
                    <button onclick="sessionManager.logout()" 
                            style="width: 100%; padding: 10px; background: transparent; 
                                   border: 1px solid #856404; border-radius: 5px; 
                                   cursor: pointer; margin-top: 10px; color: #856404;">
                        Logout Now
                    </button>
                </div>
            `;
            document.body.appendChild(modal);
        }
    }
    
    async extendSession() {
        const token = this.getToken();
        
        try {
            const response = await fetch('/api/extend-session', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                this.setToken(data.token);
                
                // Remove warning modal
                const modal = document.getElementById('session-warning');
                if (modal) modal.remove();
            }
        } catch (error) {
            console.error('Session extension error:', error);
        }
    }
    
    async logout() {
        const token = this.getToken();
        
        try {
            await fetch('/api/logout', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            this.clearToken();
            this.redirectToLogin();
        }
    }
    
    redirectToLogin() {
        // Clear all session data
        sessionStorage.clear();
        
        // Redirect to login
        window.location.href = '/login';
    }
}

// Initialize session manager
const sessionManager = new SessionManager();

// Validate session on page load
if (!window.location.pathname.includes('/login')) {
    sessionManager.validateSession();
}
```

#### 3. Protected Page Template

```html
<!-- Example: Dashboard page with authentication -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SensorWatch - Dashboard</title>
</head>
<body>
    <div id="loading">Loading...</div>
    <div id="content" style="display: none;">
        <!-- Dashboard content here -->
        <header>
            <h1>Dashboard</h1>
            <button onclick="sessionManager.logout()">Logout</button>
        </header>
        
        <main>
            <!-- Your existing dashboard HTML -->
        </main>
    </div>
    
    <script src="/js/session-manager.js"></script>
    <script>
        // Verify authentication before showing content
        (async function() {
            const isAuthenticated = await sessionManager.validateSession();
            
            if (isAuthenticated) {
                document.getElementById('loading').style.display = 'none';
                document.getElementById('content').style.display = 'block';
                
                // Initialize dashboard
                initializeDashboard();
            }
        })();
        
        function initializeDashboard() {
            // Your existing dashboard initialization code
        }
        
        // Add authentication to all API calls
        async function authenticatedFetch(url, options = {}) {
            const token = sessionManager.getToken();
            
            const headers = {
                ...options.headers,
                'Authorization': `Bearer ${token}`
            };
            
            try {
                const response = await fetch(url, { ...options, headers });
                
                // Handle 401 Unauthorized
                if (response.status === 401) {
                    sessionManager.redirectToLogin();
                    return null;
                }
                
                return response;
            } catch (error) {
                console.error('API error:', error);
                throw error;
            }
        }
    </script>
</body>
</html>
```

**Deliverables:**
- [ ] Remove client-side credential validation
- [ ] Implement server-side authentication
- [ ] Create session management system
- [ ] Add authentication to all protected pages
- [ ] Implement session timeout warnings
- [ ] Add logout functionality

**Dependencies:** Firmware team (authentication API endpoints)

---

## HIGH PRIORITY

### H1: Implement Content Security Policy (CSP)
**How Discovered:**
No CSP headers present, allowing inline scripts and potential XSS attacks.

**Security Impact:**
- XSS vulnerabilities more easily exploitable
- No protection against code injection
- Malicious scripts can execute freely

**Required Fix:**
Add CSP meta tag and remove all inline JavaScript.

**Step 1: Add CSP Meta Tag**
```html
<head>
    <meta http-equiv="Content-Security-Policy" 
          content="
            default-src 'self';
            script-src 'self' 'nonce-RANDOM_NONCE_HERE';
            style-src 'self' 'nonce-RANDOM_NONCE_HERE';
            img-src 'self' data:;
            connect-src 'self';
            font-src 'self';
            object-src 'none';
            base-uri 'self';
            form-action 'self';
            frame-ancestors 'none';
          ">
</head>
```

**Step 2: Move Inline Scripts to External Files**

**BEFORE (Inline - Insecure):**
```html
<button onclick="deleteFile()">Delete</button>

<script>
function deleteFile() {
    // Delete logic
}
</script>
```

**AFTER (External - Secure):**
```html
<button id="delete-button">Delete</button>

<script src="/js/file-manager.js" nonce="RANDOM_NONCE"></script>
```

```javascript
// /js/file-manager.js
document.getElementById('delete-button').addEventListener('click', function() {
    // Delete logic
});
```

**Step 3: Generate Nonces Dynamically**

In firmware (main.cpp):
```cpp
String generateCSPNonce() {
    uint8_t randomBytes[16];
    esp_fill_random(randomBytes, 16);
    
    char nonce[33];
    for(int i = 0; i < 16; i++) {
        sprintf(nonce + (i * 2), "%02x", randomBytes[i]);
    }
    return String(nonce);
}

server.on("/", HTTP_GET, []() {
    if (!requireAuth(server)) return;
    
    String nonce = generateCSPNonce();
    
    // Add CSP header with nonce
    String csp = "default-src 'self'; script-src 'self' 'nonce-" + nonce + "';";
    server.sendHeader("Content-Security-Policy", csp);
    
    // Generate HTML with nonce in script tags
    String html = generateHTML(nonce);
    server.send(200, "text/html", html);
});
```

**Deliverables:**
- [ ] Define CSP policy
- [ ] Move all inline scripts to external files
- [ ] Move all inline styles to external stylesheets
- [ ] Implement nonce generation
- [ ] Test CSP in report-only mode first
- [ ] Deploy enforcing CSP

---

### H2: Add Client-Side Input Validation
**How Discovered:**
Form inputs lack validation, sending invalid data to server.

**Security Impact:**
- Poor user experience
- Unnecessary server load
- Potential for injection attacks

**Required Fix:**
Implement comprehensive client-side validation (server-side validation still required).

```javascript
// validators.js

const Validators = {
    sensorId: {
        pattern: /^[A-F0-9]{16}$/,
        message: 'Sensor ID must be 16 hexadecimal characters'
    },
    
    temperature: {
        validate: (value) => {
            const num = parseFloat(value);
            return !isNaN(num) && num >= -50 && num <= 150;
        },
        message: 'Temperature must be between -50°F and 150°F'
    },
    
    filename: {
        validate: (value) => {
            // No path traversal
            if (value.includes('..') || value.includes('/') || value.includes('\\')) {
                return false;
            }
            // Valid characters only
            return /^[a-zA-Z0-9_\-\.]+$/.test(value);
        },
        message: 'Filename contains invalid characters'
    },
    
    wifiSSID: {
        validate: (value) => {
            return value.length >= 1 && value.length <= 32;
        },
        message: 'SSID must be 1-32 characters'
    },
    
    wifiPassword: {
        validate: (value) => {
            return value.length >= 8 && value.length <= 63;
        },
        message: 'Password must be 8-63 characters'
    }
};

function validateInput(value, validatorKey) {
    const validator = Validators[validatorKey];
    
    if (!validator) {
        console.error(`Unknown validator: ${validatorKey}`);
        return { valid: false, message: 'Validation error' };
    }
    
    let isValid;
    if (validator.pattern) {
        isValid = validator.pattern.test(value);
    } else if (validator.validate) {
        isValid = validator.validate(value);
    } else {
        isValid = false;
    }
    
    return {
        valid: isValid,
        message: isValid ? '' : validator.message
    };
}

function sanitizeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// Form validation helper
function setupFormValidation(formId) {
    const form = document.getElementById(formId);
    
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        
        let isValid = true;
        const formData = new FormData(form);
        
        // Validate all inputs with data-validator attribute
        form.querySelectorAll('[data-validator]').forEach(input => {
            const validatorKey = input.dataset.validator;
            const value = input.value;
            const result = validateInput(value, validatorKey);
            
            const errorElement = input.parentElement.querySelector('.error-message');
            
            if (!result.valid) {
                isValid = false;
                input.classList.add('invalid');
                if (errorElement) {
                    errorElement.textContent = result.message;
                    errorElement.style.display = 'block';
                }
            } else {
                input.classList.remove('invalid');
                if (errorElement) {
                    errorElement.style.display = 'none';
                }
            }
        });
        
        if (isValid) {
            // Submit form
            form.submit();
        }
    });
    
    // Real-time validation on blur
    form.querySelectorAll('[data-validator]').forEach(input => {
        input.addEventListener('blur', function() {
            const validatorKey = this.dataset.validator;
            const result = validateInput(this.value, validatorKey);
            
            const errorElement = this.parentElement.querySelector('.error-message');
            
            if (!result.valid) {
                this.classList.add('invalid');
                if (errorElement) {
                    errorElement.textContent = result.message;
                    errorElement.style.display = 'block';
                }
            } else {
                this.classList.remove('invalid');
                if (errorElement) {
                    errorElement.style.display = 'none';
                }
            }
        });
    });
}
```

**HTML Usage:**
```html
<form id="sensor-form">
    <div class="form-group">
        <label for="sensor-id">Sensor ID</label>
        <input 
            type="text" 
            id="sensor-id" 
            name="sensor_id"
            data-validator="sensorId"
            maxlength="16"
            required
        >
        <span class="error-message" style="display: none;"></span>
    </div>
    
    <div class="form-group">
        <label for="temperature">Temperature (°F)</label>
        <input 
            type="number" 
            id="temperature" 
            name="temperature"
            data-validator="temperature"
            min="-50"
            max="150"
            step="0.1"
            required
        >
        <span class="error-message" style="display: none;"></span>
    </div>
    
    <button type="submit">Submit</button>
</form>

<script>
    setupFormValidation('sensor-form');
</script>
```

**CSS:**
```css
.form-group input.invalid {
    border-color: #dc3545;
}

.error-message {
    color: #dc3545;
    font-size: 0.875rem;
    margin-top: 0.25rem;
}
```

**Deliverables:**
- [ ] Create validation library
- [ ] Add validation to all forms
- [ ] Implement real-time feedback
- [ ] Add HTML5 validation attributes
- [ ] Test all validation rules

---

## MEDIUM PRIORITY

### M1: Implement Secure Session Handling
**Action:** Add proper session indicators and security.

```javascript
// secure-session.js

class SecureSession {
    constructor() {
        this.sessionKey = 'session_data';
        this.encryptionKey = null;
        this.initializeEncryption();
    }
    
    async initializeEncryption() {
        // Generate encryption key from password
        const password = 'session-encryption-key'; // Should come from server
        const encoder = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            { name: 'PBKDF2' },
            false,
            ['deriveBits', 'deriveKey']
        );
        
        this.encryptionKey = await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: encoder.encode('sensorwatch-salt'),
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }
    
    async encryptData(data) {
        const encoder = new TextEncoder();
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        
        const encrypted = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            this.encryptionKey,
            encoder.encode(JSON.stringify(data))
        );
        
        // Combine IV and encrypted data
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(encrypted), iv.length);
        
        // Convert to base64
        return btoa(String.fromCharCode(...combined));
    }
    
    async decryptData(encryptedData) {
        try {
            // Decode base64
            const combined = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));
            
            // Split IV and encrypted data
            const iv = combined.slice(0, 12);
            const encrypted = combined.slice(12);
            
            const decrypted = await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                this.encryptionKey,
                encrypted
            );
            
            const decoder = new TextDecoder();
            return JSON.parse(decoder.decode(decrypted));
        } catch (error) {
            console.error('Decryption failed:', error);
            return null;
        }
    }
    
    async saveSecurely(key, value) {
        const encrypted = await this.encryptData({ [key]: value });
        sessionStorage.setItem(this.sessionKey, encrypted);
    }
    
    async getSecurely(key) {
        const encrypted = sessionStorage.getItem(this.sessionKey);
        if (!encrypted) return null;
        
        const data = await this.decryptData(encrypted);
        return data ? data[key] : null;
    }
    
    clearAll() {
        sessionStorage.clear();
    }
}

const secureSession = new SecureSession();
```

---

### M2: Add Security Indicators to UI
**Action:** Show connection and session status.

```html
<div id="security-status" style="position: fixed; top: 10px; right: 10px; 
                                  background: white; padding: 10px; 
                                  border-radius: 5px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
    <div style="display: flex; align-items: center; gap: 10px;">
        <span id="https-indicator" title="Secure HTTPS Connection">
            🔒 Secure
        </span>
        <span id="session-indicator" title="Session active"></span>
    </div>
</div>

<script>
function updateSecurityIndicators() {
    // Check HTTPS
    const httpsIndicator = document.getElementById('https-indicator');
    if (window.location.protocol === 'https:') {
        httpsIndicator.innerHTML = '🔒 Secure';
        httpsIndicator.style.color = '#28a745';
    } else {
        httpsIndicator.innerHTML = '⚠️ Insecure';
        httpsIndicator.style.color = '#dc3545';
    }
    
    // Show session status
    const sessionIndicator = document.getElementById('session-indicator');
    const token = sessionManager.getToken();
    
    if (token) {
        sessionIndicator.innerHTML = '✓ Authenticated';
        sessionIndicator.style.color = '#28a745';
    } else {
        sessionIndicator.innerHTML = '✗ Not authenticated';
        sessionIndicator.style.color = '#dc3545';
    }
}

// Update indicators on page load and periodically
updateSecurityIndicators();
setInterval(updateSecurityIndicators, 30000); // Every 30 seconds
</script>
```

---

### M3: Upgrade to WSS (Secure WebSocket)
**Action:** Replace ws:// with wss:// for WebSocket connections.

```javascript
// BEFORE (Insecure)
const ws = new WebSocket('ws://' + window.location.hostname + ':81');

// AFTER (Secure)
const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const port = window.location.protocol === 'https:' ? '443' : '81';
const ws = new WebSocket(`${protocol}//${window.location.hostname}:${port}`);

// Add authentication token to WebSocket connection
ws.onopen = function() {
    const token = sessionManager.getToken();
    
    // Send authentication message
    ws.send(JSON.stringify({
        type: 'auth',
        token: token
    }));
};

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    
    // Handle different message types
    if (data.type === 'auth_response') {
        if (data.success) {
            console.log('✓ WebSocket authenticated');
        } else {
            console.error('✗ WebSocket authentication failed');
            ws.close();
            sessionManager.redirectToLogin();
        }
    } else if (data.type === 'sensor_data') {
        updateSensorDisplay(data);
    }
};

ws.onerror = function(error) {
    console.error('WebSocket error:', error);
};

ws.onclose = function() {
    console.log('WebSocket closed, attempting reconnect...');
    setTimeout(connectWebSocket, 5000);
};
```

---

### M4: Implement File Upload Validation
**Action:** Validate files before upload.

```javascript
function validateFileUpload(file) {
    // Allowed extensions
    const allowedExtensions = ['.txt', '.json', '.csv'];
    const fileExtension = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
    
    if (!allowedExtensions.includes(fileExtension)) {
        return {
            valid: false,
            message: `File type not allowed. Allowed types: ${allowedExtensions.join(', ')}`
        };
    }
    
    // Maximum file size: 1MB
    const maxSize = 1024 * 1024;
    if (file.size > maxSize) {
        return {
            valid: false,
            message: `File too large. Maximum size: ${maxSize / 1024}KB`
        };
    }
    
    // Validate filename
    const filenameRegex = /^[a-zA-Z0-9_\-\.]+$/;
    if (!filenameRegex.test(file.name)) {
        return {
            valid: false,
            message: 'Filename contains invalid characters'
        };
    }
    
    return { valid: true };
}

// File upload handler
document.getElementById('file-input').addEventListener('change', function(e) {
    const file = e.target.files[0];
    
    if (!file) return;
    
    const validation = validateFileUpload(file);
    
    if (!validation.valid) {
        alert(validation.message);
        e.target.value = ''; // Clear input
        return;
    }
    
    // Proceed with upload
    uploadFile(file);
});

async function uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);
    
    const token = sessionManager.getToken();
    
    try {
        const response = await fetch('/api/upload', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            },
            body: formData
        });
        
        if (response.ok) {
            alert('File uploaded successfully');
        } else {
            alert('Upload failed');
        }
    } catch (error) {
        console.error('Upload error:', error);
        alert('Upload failed');
    }
}
```

---

## TESTING REQUIREMENTS

### Client-Side Security Tests

1. **Authentication Tests:**
```javascript
// Test that unauthenticated access redirects to login
async function testUnauthenticatedAccess() {
    sessionManager.clearToken();
    
    const response = await fetch('/dashboard');
    
    // Should redirect to /login
    console.assert(
        window.location.pathname === '/login',
        'Unauthenticated access should redirect to login'
    );
}
```

2. **Input Validation Tests:**
```javascript
function testInputValidation() {
    // Test valid sensor ID
    let result = validateInput('ABC123DEF4567890', 'sensorId');
    console.assert(result.valid === true, 'Valid sensor ID should pass');
    
    // Test invalid sensor ID (SQL injection attempt)
    result = validateInput("' OR '1'='1", 'sensorId');
    console.assert(result.valid === false, 'SQL injection should be blocked');
    
    // Test XSS attempt
    result = validateInput('<script>alert("XSS")</script>', 'filename');
    console.assert(result.valid === false, 'XSS attempt should be blocked');
}
```

3. **CSP Compliance Tests:**
```javascript
// Check that CSP is enforced
function testCSP() {
    // Try to execute inline script (should be blocked by CSP)
    const script = document.createElement('script');
    script.textContent = 'console.log("This should be blocked")';
    
    try {
        document.body.appendChild(script);
        console.error('CSP FAILED: Inline script was not blocked');
    } catch (error) {
        console.log('✓ CSP working: Inline script blocked');
    }
}
```

---

## DEPENDENCIES

### From Firmware Team
- [ ] Authentication API endpoints
- [ ] Session management backend
- [ ] HTTPS enabled on web server
- [ ] WebSocket authentication support

### From Security Team
- [ ] CSP policy requirements
- [ ] Security header specifications
- [ ] Authentication token format
- [ ] Session timeout values

---

## DEPLOYMENT CHECKLIST

- [ ] Remove all client-side authentication
- [ ] Implement server-side authentication
- [ ] Add session management
- [ ] Implement CSP
- [ ] Move inline scripts to external files
- [ ] Add input validation
- [ ] Upgrade WebSocket to WSS
- [ ] Add security indicators
- [ ] Test all security controls
- [ ] Update documentation

---

**Report Generated:** Security Audit Team  
**Document Version:** 1.0  
**Last Updated:** December 16, 2025
