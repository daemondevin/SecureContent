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