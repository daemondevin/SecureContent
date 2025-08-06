# Secure Content Server
A comprehensive server-side protection system.

## Installation Requirements

- PHP 7.4 or higher
- SQLite extension enabled
- Web server (Apache/Nginx)
- Write permissions for database files

## Setup Instructions

### 1. File Structure
```
secure_content/
    ├── index.html               (Secure content viewer)
    ├── secure_server.php        (Main server-side protection)
    ├── config.php               (Configuration file)
    ├── .htaccess                (Apache security rules)
    └── data/                    
        ├── secure_sessions.db   (SQLite database)
        ├── secret.key           (Unique secret)
        └── logs/                (Logs directory)
```

### 2. Configuration File (config.php)
```php
<?php
// Security Configuration
define('SECRET_KEY_FILE', 'data/secret.key');
define('DATABASE_FILE', 'data/secure_sessions.db');
define('MAX_SESSION_TIME', 300); // 5 minutes default
define('RATE_LIMIT_SECONDS', 60); // 1 minute between token requests
define('MAX_SUSPICIOUS_ACTIVITIES', 3); // Auto-expire after 3 suspicious activities
define('CLEANUP_INTERVAL', 3600); // Cleanup every hour
define('LOG_RETENTION_HOURS', 24); // Keep logs for 24 hours

// CORS Settings (restrict in production)
define('ALLOWED_ORIGINS', '*'); // Change to your domain: 'https://yourdomain.com'
define('ALLOWED_METHODS', 'POST, GET, OPTIONS');

// IP Validation Settings
define('ENFORCE_IP_VALIDATION', false); // Set to true for strict IP checking
define('MOBILE_IP_TOLERANCE', true); // Allow IP changes for mobile devices

// Debug Settings
define('DEBUG_MODE', false); // Set to false in production
define('LOG_ALL_REQUESTS', true); // Log all API requests

// Database Settings
define('DB_ENCRYPTION', false); // Enable for sensitive data encryption
?>
```

### 3. Apache Security (.htaccess)
```apache
# Deny access to sensitive files
<Files "config.php">
    Order Allow,Deny
    Deny from all
</Files>

<Files "secret.key">
    Order Allow,Deny
    Deny from all
</Files>

<Files "*.db">
    Order Allow,Deny
    Deny from all
</Files>

# Security headers
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "no-referrer"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"

# Disable server signature
ServerTokens Prod
```

### 4. Nginx Configuration (if using Nginx)
```nginx
location ~ \.(db|key)$ {
    deny all;
    return 404;
}

location ~ config\.php$ {
    deny all;
    return 404;
}

location ~ /data/ {
    deny all;
    return 404;
}

# Security headers
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer" always;
```

## API Endpoints

### Generate Token
```http
POST /secure_server.php
Content-Type: application/x-www-form-urlencoded

action=generate_token&time_limit=300&user_id=optional_user_id
```

### Validate Token
```http
POST /secure_server.php
Content-Type: application/x-www-form-urlencoded

action=validate_token&token=SESSION_TOKEN_HERE
```

### Report Suspicious Activity
```http
POST /secure_server.php
Content-Type: application/x-www-form-urlencoded

action=report_suspicious&token=SESSION_TOKEN&activity=screenshot_attempt&details=Print Screen key detected
```

### Expire Session
```http
POST /secure_server.php
Content-Type: application/x-www-form-urlencoded

action=expire_session&token=SESSION_TOKEN
```

### Get Session Statistics
```http
GET /secure_server.php?action=stats&token=SESSION_TOKEN
```

### Cleanup Expired Sessions
```http
POST /secure_server.php
Content-Type: application/x-www-form-urlencoded

action=cleanup
```

## Security Features

### Server-Side Protection
- **Token-based Authentication**: Secure HMAC-signed tokens with expiration
- **Session Tracking**: SQLite database tracks all sessions and activities
- **IP Address Monitoring**: Optional IP validation (can be disabled for mobile)
- **Rate Limiting**: Prevents token generation abuse
- **Suspicious Activity Logging**: Tracks and responds to security threats
- **Auto-cleanup**: Removes expired sessions and old logs

### Database Schema
```sql
-- Sessions table
CREATE TABLE secure_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_token VARCHAR(255) UNIQUE,
    user_id VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    access_count INTEGER DEFAULT 0,
    last_access DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_expired BOOLEAN DEFAULT 0,
    suspicious_activity TEXT
);

-- Access logs table
CREATE TABLE access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_token VARCHAR(255),
    action VARCHAR(100),
    details TEXT,
    ip_address VARCHAR(45),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## Deployment Steps

### 1. Upload Files
```bash
# Upload all files to your web server
scp -r secure_content/ user@yourserver:/var/www/html/
```

### 2. Set Permissions
```bash
# Create data directory
mkdir -p /var/www/html/secure_content/data/logs

# Set proper permissions
chmod 755 /var/www/html/secure_content/
chmod 644 /var/www/html/secure_content/*.php
chmod 644 /var/www/html/secure_content/*.html
chmod 700 /var/www/html/secure_content/data/
chmod 600 /var/www/html/secure_content/data/* 2>/dev/null || true

# Set ownership (adjust user/group as needed)
chown -R www-data:www-data /var/www/html/secure_content/
```

### 3. Test Installation
```bash
# Test token generation
curl -X POST https://yourdomain.com/secure_content/secure_server.php \
  -d "action=generate_token&time_limit=300"

# Expected response:
# {"success":true,"token":"eyJ1c2VyX2lkIjoiYW5vbnltb3V...","expires_in":300}
```

### 4. Configure Cron Job for Cleanup
```bash
# Add to crontab (runs every hour)
0 * * * * curl -X POST https://yourdomain.com/secure_content/secure_server.php -d "action=cleanup" >/dev/null 2>&1
```

## Production Security Checklist

### Server Configuration
- [ ] Change default secret key
- [ ] Restrict CORS origins to your domain
- [ ] Enable HTTPS only
- [ ] Set proper file permissions (600 for sensitive files)
- [ ] Configure firewall rules
- [ ] Enable fail2ban or similar intrusion prevention

### PHP Configuration
- [ ] Disable `display_errors` in production
- [ ] Set appropriate `memory_limit`
- [ ] Configure proper `session` settings
- [ ] Enable `opcache` for performance

### Database Security
- [ ] Regular database backups
- [ ] Monitor database size and performance
- [ ] Consider encryption for sensitive data
- [ ] Set up log rotation

### Monitoring
- [ ] Set up access log monitoring
- [ ] Monitor suspicious activity patterns
- [ ] Track token generation rates
- [ ] Monitor server resources

## Troubleshooting

### Common Issues

**"Database initialization failed"**
- Check PHP SQLite extension: `php -m | grep sqlite`
- Verify write permissions on data directory
- Check PHP error logs

**"Token generation failed"**
- Verify secret key file permissions
- Check database write permissions
- Review PHP error logs

**"Rate limit exceeded"**
- Wait 60 seconds between requests
- Check if rate limit files are being created
- Adjust `RATE_LIMIT_SECONDS` in config

**Client-server communication fails**
- Verify CORS settings
- Check network connectivity
- Review browser console for errors
- Confirm server endpoint URL

### Debug Mode
Enable debug mode in config.php for detailed logging:
```php
define('DEBUG_MODE', true);
define('LOG_ALL_REQUESTS', true);
```

### Log Locations
- PHP error log: `/var/log/php/error.log` (varies by system)
- Apache error log: `/var/log/apache2/error.log`
- Application logs: `data/logs/` directory

## Advanced Configuration

### Custom Time Limits
```javascript
// Client-side: 10 minutes
const secureViewer = new SecureContentViewer(10 * 60 * 1000, 'secure_server.php');
```

```php
// Server-side: Custom limits per user
$timeLimit = ($userId === 'premium_user') ? 1800 : 300; // 30 min vs 5 min
```

### IP Whitelist/Blacklist
```php
// In secure_server.php, add IP filtering
$allowedIPs = ['192.168.1.100', '10.0.0.50'];
$clientIP = $_SERVER['REMOTE_ADDR'];

if (!in_array($clientIP, $allowedIPs)) {
    http_response_code(403);
    echo json_encode(['error' => 'Access denied']);
    exit;
}
```

### Custom Suspicious Activity Rules
```javascript
// Client-side: Custom detection
secureViewer.reportSuspiciousActivity('custom_event', 'User performed restricted action');
```

### Integration with Existing Authentication
```php
// Validate existing user session before generating token
session_start();
if (!isset($_SESSION['authenticated_user'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Authentication required']);
    exit;
}

$userId = $_SESSION['user_id'];
$token = $manager->generateSessionToken($userId, $timeLimit);
```

## Performance Optimization

### Database Optimization
- Add indexes for frequently queried columns
- Implement connection pooling for high traffic
- Consider moving to MySQL/PostgreSQL for large deployments

### Caching
- Implement Redis/Memcached for session data
- Cache validation results for short periods
- Use CDN for static assets

### Load Balancing
- Share secret key across multiple servers
- Use centralized database for sessions
- Implement sticky sessions if needed

## Compliance and Legal

### GDPR Considerations
- Log only necessary data
- Implement data retention policies
- Provide data deletion capabilities
- Document data processing activities

### CCPA Compliance
- Allow users to request data deletion
- Provide transparency about data collection
- Implement opt-out mechanisms

## Support and Maintenance

### Regular Tasks
- Monitor log file sizes
- Review suspicious activity reports
- Update secret keys periodically
- Test backup and recovery procedures
- Update PHP and server software

### Security Updates
- Keep PHP version updated
- Monitor security advisories
- Review and update security headers
- Audit access logs regularly
