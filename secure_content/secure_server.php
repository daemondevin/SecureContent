<?php
/**
 * Secure Content Server-Side Protection System
 * Works with the JavaScript client for comprehensive security
 */
class SecureContentManager {
    private $dbFile = 'secure_sessions.db';
    private $secretKey = 'your-secret-key-change-this'; // Change this in production
    private $maxSessionTime = 300; // 5 minutes default
    
    public function __construct() {
        $this->initDatabase();
        $this->secretKey = $this->getOrCreateSecretKey();
    }
    
    /**
     * Initialize SQLite database for session tracking
     */
    private function initDatabase() {
        try {
            $pdo = new PDO("sqlite:" . $this->dbFile);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $pdo->exec("
                CREATE TABLE IF NOT EXISTS secure_sessions (
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
                )
            ");
            
            $pdo->exec("
                CREATE TABLE IF NOT EXISTS access_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_token VARCHAR(255),
                    action VARCHAR(100),
                    details TEXT,
                    ip_address VARCHAR(45),
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ");
            
        } catch (PDOException $e) {
            error_log("Database initialization failed: " . $e->getMessage());
            throw new Exception("System initialization failed");
        }
    }
    
    /**
     * Get or create a secret key for token generation
     */
    private function getOrCreateSecretKey() {
        $keyFile = 'secret.key';
        if (file_exists($keyFile)) {
            return file_get_contents($keyFile);
        }
        
        $key = bin2hex(random_bytes(32));
        file_put_contents($keyFile, $key);
        chmod($keyFile, 0600); // Restrict access
        return $key;
    }
    
    /**
     * Generate a secure session token
     */
    public function generateSessionToken($userId = null, $timeLimit = null) {
        $timeLimit = $timeLimit ?: $this->maxSessionTime;
        $userId = $userId ?: 'anonymous_' . uniqid();
        
        $payload = [
            'user_id' => $userId,
            'created_at' => time(),
            'expires_at' => time() + $timeLimit,
            'random' => bin2hex(random_bytes(16))
        ];
        
        $token = base64_encode(json_encode($payload)) . '.' . 
                 hash_hmac('sha256', base64_encode(json_encode($payload)), $this->secretKey);
        
        // Store in database
        try {
            $pdo = new PDO("sqlite:" . $this->dbFile);
            $stmt = $pdo->prepare("
                INSERT INTO secure_sessions 
                (session_token, user_id, ip_address, user_agent, expires_at) 
                VALUES (?, ?, ?, ?, ?)
            ");
            
            $stmt->execute([
                $token,
                $userId,
                $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
                date('Y-m-d H:i:s', time() + $timeLimit)
            ]);
            
            $this->logAccess($token, 'token_generated', 'New session token created');
            
        } catch (PDOException $e) {
            error_log("Token storage failed: " . $e->getMessage());
            throw new Exception("Token generation failed");
        }
        
        return $token;
    }
    
    /**
     * Validate a session token
     */
    public function validateToken($token) {
        if (empty($token)) {
            return ['valid' => false, 'reason' => 'No token provided'];
        }
        
        // Basic token format validation
        $parts = explode('.', $token);
        if (count($parts) !== 2) {
            return ['valid' => false, 'reason' => 'Invalid token format'];
        }
        
        [$payload, $signature] = $parts;
        
        // Verify signature
        $expectedSignature = hash_hmac('sha256', $payload, $this->secretKey);
        if (!hash_equals($expectedSignature, $signature)) {
            $this->logAccess($token, 'validation_failed', 'Invalid signature');
            return ['valid' => false, 'reason' => 'Invalid token signature'];
        }
        
        // Decode payload
        try {
            $data = json_decode(base64_decode($payload), true);
        } catch (Exception $e) {
            return ['valid' => false, 'reason' => 'Invalid token data'];
        }
        
        // Check expiration
        if ($data['expires_at'] < time()) {
            $this->expireSession($token);
            return ['valid' => false, 'reason' => 'Token expired'];
        }
        
        // Check database record
        try {
            $pdo = new PDO("sqlite:" . $this->dbFile);
            $stmt = $pdo->prepare("
                SELECT * FROM secure_sessions 
                WHERE session_token = ? AND is_expired = 0
            ");
            $stmt->execute([$token]);
            $session = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$session) {
                return ['valid' => false, 'reason' => 'Session not found or expired'];
            }
            
            // Additional security checks
            $currentIP = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $currentUA = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
            
            // IP address change detection (optional - can be disabled for mobile)
            if ($session['ip_address'] !== $currentIP) {
                $this->logAccess($token, 'ip_change', "IP changed from {$session['ip_address']} to {$currentIP}");
                // Uncomment to enforce strict IP checking:
                // return ['valid' => false, 'reason' => 'IP address mismatch'];
            }
            
            // Update access tracking
            $this->updateAccess($token);
            
            return [
                'valid' => true,
                'session' => $session,
                'remaining_time' => strtotime($session['expires_at']) - time()
            ];
            
        } catch (PDOException $e) {
            error_log("Token validation failed: " . $e->getMessage());
            return ['valid' => false, 'reason' => 'Validation error'];
        }
    }
    
    /**
     * Update session access tracking
     */
    private function updateAccess($token) {
        try {
            $pdo = new PDO("sqlite:" . $this->dbFile);
            $stmt = $pdo->prepare("
                UPDATE secure_sessions 
                SET access_count = access_count + 1, last_access = CURRENT_TIMESTAMP 
                WHERE session_token = ?
            ");
            $stmt->execute([$token]);
            
        } catch (PDOException $e) {
            error_log("Access update failed: " . $e->getMessage());
        }
    }
    
    /**
     * Expire a session
     */
    public function expireSession($token) {
        try {
            $pdo = new PDO("sqlite:" . $this->dbFile);
            $stmt = $pdo->prepare("
                UPDATE secure_sessions 
                SET is_expired = 1 
                WHERE session_token = ?
            ");
            $stmt->execute([$token]);
            
            $this->logAccess($token, 'session_expired', 'Session manually expired');
            
        } catch (PDOException $e) {
            error_log("Session expiration failed: " . $e->getMessage());
        }
    }
    
    /**
     * Report suspicious activity
     */
    public function reportSuspiciousActivity($token, $activity, $details = '') {
        try {
            $pdo = new PDO("sqlite:" . $this->dbFile);
            
            // Update session with suspicious activity
            $stmt = $pdo->prepare("
                UPDATE secure_sessions 
                SET suspicious_activity = COALESCE(suspicious_activity, '') || ? || '; '
                WHERE session_token = ?
            ");
            $stmt->execute([
                date('Y-m-d H:i:s') . ": {$activity} - {$details}",
                $token
            ]);
            
            $this->logAccess($token, 'suspicious_activity', "{$activity}: {$details}");
            
            // Auto-expire session after multiple suspicious activities
            $stmt = $pdo->prepare("
                SELECT suspicious_activity FROM secure_sessions WHERE session_token = ?
            ");
            $stmt->execute([$token]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($result && substr_count($result['suspicious_activity'], ';') >= 3) {
                $this->expireSession($token);
                return ['action' => 'session_expired', 'reason' => 'Multiple suspicious activities'];
            }
            
            return ['action' => 'logged', 'reason' => 'Activity recorded'];
            
        } catch (PDOException $e) {
            error_log("Suspicious activity reporting failed: " . $e->getMessage());
            return ['action' => 'error', 'reason' => 'Reporting failed'];
        }
    }
    
    /**
     * Log access attempts
     */
    private function logAccess($token, $action, $details = '') {
        try {
            $pdo = new PDO("sqlite:" . $this->dbFile);
            $stmt = $pdo->prepare("
                INSERT INTO access_logs (session_token, action, details, ip_address) 
                VALUES (?, ?, ?, ?)
            ");
            $stmt->execute([
                $token,
                $action,
                $details,
                $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
            
        } catch (PDOException $e) {
            error_log("Access logging failed: " . $e->getMessage());
        }
    }
    
    /**
     * Clean up expired sessions
     */
    public function cleanupExpiredSessions() {
        try {
            $pdo = new PDO("sqlite:" . $this->dbFile);
            
            // Expire old sessions
            $stmt = $pdo->prepare("
                UPDATE secure_sessions 
                SET is_expired = 1 
                WHERE expires_at < CURRENT_TIMESTAMP AND is_expired = 0
            ");
            $stmt->execute();
            
            // Delete very old records (older than 24 hours)
            $stmt = $pdo->prepare("
                DELETE FROM secure_sessions 
                WHERE created_at < datetime('now', '-1 day')
            ");
            $stmt->execute();
            
            $stmt = $pdo->prepare("
                DELETE FROM access_logs 
                WHERE timestamp < datetime('now', '-1 day')
            ");
            $stmt->execute();
            
        } catch (PDOException $e) {
            error_log("Cleanup failed: " . $e->getMessage());
        }
    }
    
    /**
     * Get session statistics
     */
    public function getSessionStats($token) {
        try {
            $pdo = new PDO("sqlite:" . $this->dbFile);
            $stmt = $pdo->prepare("
                SELECT 
                    s.*,
                    COUNT(l.id) as total_actions
                FROM secure_sessions s 
                LEFT JOIN access_logs l ON s.session_token = l.session_token 
                WHERE s.session_token = ? 
                GROUP BY s.id
            ");
            $stmt->execute([$token]);
            
            return $stmt->fetch(PDO::FETCH_ASSOC);
            
        } catch (PDOException $e) {
            error_log("Stats retrieval failed: " . $e->getMessage());
            return null;
        }
    }
}

// API Endpoints
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *'); // Restrict this in production
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

$manager = new SecureContentManager();

// Handle different API endpoints
$action = $_GET['action'] ?? $_POST['action'] ?? '';

switch ($action) {
    case 'generate_token':
        try {
            $timeLimit = intval($_POST['time_limit'] ?? 300); // Default 5 minutes
            $userId = $_POST['user_id'] ?? null;
            
            // Basic rate limiting
            $rateLimitKey = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $rateLimitFile = "rate_limit_{$rateLimitKey}.txt";
            
            if (file_exists($rateLimitFile)) {
                $lastRequest = file_get_contents($rateLimitFile);
                if (time() - $lastRequest < 60) { // 1 minute between requests
                    http_response_code(429);
                    echo json_encode(['error' => 'Rate limit exceeded']);
                    exit;
                }
            }
            
            file_put_contents($rateLimitFile, time());
            
            $token = $manager->generateSessionToken($userId, $timeLimit);
            
            echo json_encode([
                'success' => true,
                'token' => $token,
                'expires_in' => $timeLimit
            ]);
            
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['error' => $e->getMessage()]);
        }
        break;
        
    case 'validate_token':
        $token = $_POST['token'] ?? $_GET['token'] ?? '';
        $validation = $manager->validateToken($token);
        
        if ($validation['valid']) {
            echo json_encode([
                'valid' => true,
                'remaining_time' => $validation['remaining_time'],
                'session_info' => [
                    'access_count' => $validation['session']['access_count'],
                    'created_at' => $validation['session']['created_at']
                ]
            ]);
        } else {
            http_response_code(401);
            echo json_encode([
                'valid' => false,
                'reason' => $validation['reason']
            ]);
        }
        break;
        
    case 'report_suspicious':
        $token = $_POST['token'] ?? '';
        $activity = $_POST['activity'] ?? '';
        $details = $_POST['details'] ?? '';
        
        if (empty($token) || empty($activity)) {
            http_response_code(400);
            echo json_encode(['error' => 'Missing required parameters']);
            break;
        }
        
        $result = $manager->reportSuspiciousActivity($token, $activity, $details);
        echo json_encode($result);
        break;
        
    case 'expire_session':
        $token = $_POST['token'] ?? '';
        
        if (empty($token)) {
            http_response_code(400);
            echo json_encode(['error' => 'Missing token']);
            break;
        }
        
        $manager->expireSession($token);
        echo json_encode(['success' => true, 'message' => 'Session expired']);
        break;
        
    case 'cleanup':
        // This should be called periodically via cron job
        $manager->cleanupExpiredSessions();
        echo json_encode(['success' => true, 'message' => 'Cleanup completed']);
        break;
        
    case 'stats':
        $token = $_GET['token'] ?? '';
        
        if (empty($token)) {
            http_response_code(400);
            echo json_encode(['error' => 'Missing token']);
            break;
        }
        
        $stats = $manager->getSessionStats($token);
        echo json_encode(['stats' => $stats]);
        break;
        
    default:
        http_response_code(400);
        echo json_encode(['error' => 'Invalid action']);
        break;
}
