# Security Recommendations for claude-devtools

This document provides actionable security recommendations for the development team, organized by priority and implementation difficulty.

---

## Quick Reference

| Priority | Recommendation | Effort | Impact | Status |
|----------|---------------|--------|--------|--------|
| 🔴 HIGH | Encrypt SSH connection details | Medium | High | Pending |
| 🔴 HIGH | Harden config file permissions | Low | Medium | Pending |
| 🟡 MEDIUM | Implement security audit logging | Medium | Medium | Pending |
| 🟡 MEDIUM | Add Content Security Policy | Low | Low | Pending |
| 🟡 MEDIUM | Add "Don't Remember" option for SSH | Low | Medium | Pending |
| 🟢 LOW | Secure memory handling for keys | Medium | Low | Pending |
| 🟢 LOW | Audit log statements for sensitive data | Medium | Low | Pending |

---

## 🔴 HIGH PRIORITY

### 1. Encrypt SSH Connection Details

**Problem:**  
SSH connection details (host, port, username, auth method, private key paths) are stored in plaintext in `~/.claude/claude-devtools-config.json`. While passwords are not stored, other sensitive metadata could aid attackers.

**Solution:**  
Implement encryption using Electron's `safeStorage` API:

```typescript
// src/main/services/infrastructure/ConfigManager.ts

import { safeStorage } from 'electron';

class ConfigManager {
  // Add encryption helpers
  private encryptSensitiveData(data: string): string {
    if (safeStorage.isEncryptionAvailable()) {
      const buffer = safeStorage.encryptString(data);
      return buffer.toString('base64');
    }
    // Fallback: store with warning
    logger.warn('Encryption not available, storing in plaintext');
    return data;
  }

  private decryptSensitiveData(encryptedData: string): string {
    if (safeStorage.isEncryptionAvailable()) {
      const buffer = Buffer.from(encryptedData, 'base64');
      return safeStorage.decryptString(buffer);
    }
    return encryptedData;
  }

  // Modify updateConfig to encrypt SSH section
  updateConfig(section: keyof AppConfig, data: Partial<AppConfig[typeof section]>): void {
    if (section === 'ssh' && data.lastConnection) {
      // Encrypt sensitive fields
      const encrypted = {
        ...data.lastConnection,
        host: this.encryptSensitiveData(data.lastConnection.host),
        username: this.encryptSensitiveData(data.lastConnection.username),
        privateKeyPath: data.lastConnection.privateKeyPath 
          ? this.encryptSensitiveData(data.lastConnection.privateKeyPath)
          : undefined,
      };
      this.config.ssh.lastConnection = encrypted;
    }
    // ... rest of method
  }
}
```

**Alternative: Use OS Credential Storage**

For even better security, use platform-specific credential storage:

```typescript
// macOS: Keychain
// Windows: Credential Manager  
// Linux: libsecret

import keytar from 'keytar';

async saveSSHCredentials(connectionId: string, credentials: SshConnectionConfig) {
  await keytar.setPassword('claude-devtools', connectionId, JSON.stringify(credentials));
}

async getSSHCredentials(connectionId: string): Promise<SshConnectionConfig | null> {
  const data = await keytar.getPassword('claude-devtools', connectionId);
  return data ? JSON.parse(data) : null;
}
```

**Testing:**
- Test on macOS (uses Keychain)
- Test on Windows (uses Data Protection API)
- Test on Linux (varies by distribution)
- Ensure fallback works when encryption unavailable

**Effort:** Medium (2-4 hours)  
**Impact:** High (protects SSH connection metadata)

---

### 2. Harden Config File Permissions

**Problem:**  
Config file inherits default permissions from OS, potentially allowing other users to read sensitive configuration.

**Solution:**  
Set restrictive permissions (600 = owner read/write only) when creating/updating config file:

```typescript
// src/main/services/infrastructure/ConfigManager.ts

import * as fs from 'fs';
import * as os from 'os';

private saveConfig(): void {
  try {
    // Ensure directory exists
    if (!fs.existsSync(CONFIG_DIR)) {
      fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 }); // drwx------
    }

    // Write config
    const json = JSON.stringify(this.config, null, 2);
    fs.writeFileSync(this.configPath, json, { 
      encoding: 'utf8',
      mode: 0o600 // -rw------- (owner read/write only)
    });

    // Verify permissions on Unix systems
    if (os.platform() !== 'win32') {
      const stats = fs.statSync(this.configPath);
      const mode = stats.mode & parseInt('777', 8);
      if (mode !== parseInt('600', 8)) {
        logger.warn(`Config file permissions (${mode.toString(8)}) are not restrictive enough`);
        fs.chmodSync(this.configPath, 0o600);
      }
    }

    logger.info('Config saved successfully with secure permissions');
  } catch (error) {
    logger.error('Failed to save config:', error);
  }
}

private loadConfig(): void {
  try {
    // ... existing load logic ...

    // Verify permissions after loading (Unix only)
    if (os.platform() !== 'win32' && fs.existsSync(this.configPath)) {
      const stats = fs.statSync(this.configPath);
      const mode = stats.mode & parseInt('777', 8);
      if (mode > parseInt('600', 8)) {
        logger.warn(`Config file has overly permissive permissions (${mode.toString(8)})`);
        logger.info('Attempting to fix permissions...');
        try {
          fs.chmodSync(this.configPath, 0o600);
        } catch (chmodError) {
          logger.error('Failed to fix permissions:', chmodError);
        }
      }
    }
  } catch (error) {
    logger.error('Failed to load config:', error);
  }
}
```

**Windows Considerations:**  
Windows uses ACLs instead of Unix permissions. Consider using PowerShell or native Windows APIs for Windows-specific hardening.

**Testing:**
- Verify file created with 600 permissions on macOS/Linux
- Test permission repair on existing files
- Ensure Windows compatibility (ACLs)

**Effort:** Low (1-2 hours)  
**Impact:** Medium (prevents local user snooping)

---

## 🟡 MEDIUM PRIORITY

### 3. Implement Security Audit Logging

**Problem:**  
Limited visibility into security-sensitive operations makes incident investigation difficult.

**Solution:**  
Add structured audit logging for security events:

```typescript
// src/shared/utils/securityLogger.ts

export interface SecurityEvent {
  timestamp: number;
  eventType: 'ssh_connect' | 'ssh_disconnect' | 'path_violation' | 'file_access' | 'auth_failure';
  severity: 'info' | 'warning' | 'error';
  details: Record<string, unknown>;
  userId?: string;
  ipAddress?: string;
}

class SecurityLogger {
  private logFile: string;

  constructor() {
    this.logFile = path.join(os.homedir(), '.claude', 'security-audit.log');
  }

  log(event: SecurityEvent): void {
    const logEntry = {
      ...event,
      timestamp: event.timestamp || Date.now(),
      version: app.getVersion(),
    };

    // Append to log file (rotate if > 10MB)
    this.appendToLog(JSON.stringify(logEntry) + '\n');

    // Also log to console in development
    if (process.env.NODE_ENV === 'development') {
      console.log('[SECURITY]', logEntry);
    }
  }

  private appendToLog(entry: string): void {
    try {
      // Check file size and rotate if needed
      if (fs.existsSync(this.logFile)) {
        const stats = fs.statSync(this.logFile);
        if (stats.size > 10 * 1024 * 1024) { // 10MB
          const backupPath = `${this.logFile}.${Date.now()}`;
          fs.renameSync(this.logFile, backupPath);
          
          // Keep only last 5 backups
          this.cleanOldBackups();
        }
      }

      fs.appendFileSync(this.logFile, entry, { mode: 0o600 });
    } catch (error) {
      console.error('Failed to write security log:', error);
    }
  }

  private cleanOldBackups(): void {
    // Implementation: keep only 5 most recent backup files
  }
}

export const securityLogger = new SecurityLogger();
```

**Usage Examples:**

```typescript
// SSH Connection
securityLogger.log({
  eventType: 'ssh_connect',
  severity: 'info',
  details: {
    host: config.host,
    port: config.port,
    username: config.username,
    authMethod: config.authMethod,
    success: true,
  },
});

// Path Validation Failure
securityLogger.log({
  eventType: 'path_violation',
  severity: 'warning',
  details: {
    requestedPath: targetPath,
    reason: validation.error,
    projectPath: projectRoot,
  },
});

// Failed SSH Authentication
securityLogger.log({
  eventType: 'auth_failure',
  severity: 'error',
  details: {
    host: config.host,
    username: config.username,
    error: err.message,
  },
});
```

**Integration Points:**
- SSH connection attempts (success/failure)
- Path validation failures
- Sensitive file access attempts
- Config file modifications
- Authentication failures

**Effort:** Medium (3-5 hours)  
**Impact:** Medium (improves incident response)

---

### 4. Add Content Security Policy (CSP)

**Problem:**  
No explicit CSP headers in production builds. While the renderer is trusted, CSP provides defense-in-depth against potential XSS if a vulnerability is introduced.

**Solution:**  
Add CSP meta tag to renderer HTML:

```html
<!-- src/renderer/index.html -->
<head>
  <meta http-equiv="Content-Security-Policy" 
        content="
          default-src 'self';
          script-src 'self';
          style-src 'self' 'unsafe-inline';
          img-src 'self' data: blob:;
          font-src 'self' data:;
          connect-src 'self' http://localhost:* http://127.0.0.1:*;
          object-src 'none';
          base-uri 'self';
          form-action 'self';
          frame-ancestors 'none';
        ">
  <!-- ... rest of head -->
</head>
```

**CSP Policy Breakdown:**
- `default-src 'self'`: Only load resources from same origin
- `script-src 'self'`: Only load scripts from application bundle
- `style-src 'self' 'unsafe-inline'`: Allow inline styles (required by Tailwind)
- `connect-src`: Allow connections to localhost HTTP server
- `object-src 'none'`: Disallow Flash, Java, etc.
- `frame-ancestors 'none'`: Prevent clickjacking

**Testing:**
- Run app and check browser console for CSP violations
- Test all features (markdown rendering, syntax highlighting, etc.)
- Adjust policy if legitimate features are blocked

**Effort:** Low (1-2 hours)  
**Impact:** Low (defense-in-depth)

---

### 5. Add "Don't Remember Connection" Option

**Problem:**  
Users have no control over whether SSH connection details are persisted. Some users may prefer not to store this information.

**Solution:**  
Add checkbox in SSH connection dialog:

```typescript
// Renderer: SSH connection form
interface SshConnectionFormData {
  // ... existing fields ...
  rememberConnection: boolean; // New field
}

// Main: SSH IPC handler
ipcMain.handle(SSH_CONNECT, async (_event, config: SshConnectionConfig, remember: boolean) => {
  try {
    await connectionManager.connect(config);

    // Only save if user opted in
    if (remember) {
      configManager.updateConfig('ssh', {
        lastConnection: {
          host: config.host,
          port: config.port,
          username: config.username,
          authMethod: config.authMethod,
          privateKeyPath: config.privateKeyPath,
        },
      });
    } else {
      // Clear any existing saved connection
      configManager.updateConfig('ssh', { lastConnection: null });
    }

    return { success: true, data: connectionManager.getStatus() };
  } catch (err) {
    // ... error handling ...
  }
});
```

**UI Changes:**
- Add checkbox to SSH connection dialog: "Remember this connection"
- Default to unchecked (opt-in for security)
- Show info tooltip explaining what's saved

**Effort:** Low (2-3 hours)  
**Impact:** Medium (user privacy control)

---

## 🟢 LOW PRIORITY

### 6. Secure Memory Handling for Private Keys

**Problem:**  
Private key material remains in memory as JavaScript strings, potentially vulnerable to memory dumps.

**Solution:**  
Overwrite sensitive data after use:

```typescript
// src/main/services/infrastructure/SshConnectionManager.ts

private async buildConnectConfig(config: SshConnectionConfig): Promise<ConnectConfig> {
  // ... existing code ...

  case 'privateKey': {
    const keyPath = config.privateKeyPath ?? path.join(os.homedir(), '.ssh', 'id_rsa');
    let keyData: string | null = null;
    try {
      keyData = await fs.promises.readFile(keyPath, 'utf8');
      connectConfig.privateKey = keyData;
      
      // ssh2 library will copy the key, so we can clear our reference
      // Note: This is limited protection as V8 may still have copies
      setTimeout(() => {
        if (keyData) {
          // Overwrite string memory (best effort)
          keyData = '0'.repeat(keyData.length);
          keyData = null;
        }
      }, 1000);
    } catch (err) {
      throw new Error(`Cannot read private key at ${keyPath}: ${(err as Error).message}`);
    }
    break;
  }
}
```

**Note:**  
JavaScript string immutability limits effectiveness. True secure memory handling requires native modules. This is a best-effort approach.

**Effort:** Medium (2-3 hours)  
**Impact:** Low (limited effectiveness in JavaScript)

---

### 7. Audit Log Statements for Sensitive Data

**Problem:**  
Logger statements may inadvertently expose sensitive data (credentials, file contents, personal data).

**Solution:**  
1. Manual audit of all logger calls
2. Implement log sanitization helper
3. Add explicit "no-log" markers

```typescript
// src/shared/utils/logSanitizer.ts

const SENSITIVE_KEYS = ['password', 'privateKey', 'token', 'secret', 'apiKey'];

export function sanitizeForLogging(obj: unknown): unknown {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map(sanitizeForLogging);
  }

  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (SENSITIVE_KEYS.some(sensitive => key.toLowerCase().includes(sensitive))) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof value === 'object') {
      sanitized[key] = sanitizeForLogging(value);
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

// Usage:
logger.info('SSH config:', sanitizeForLogging(config));
// Output: { host: 'example.com', password: '[REDACTED]', port: 22 }
```

**Audit Checklist:**
- [ ] Review all logger.debug() calls (most verbose)
- [ ] Review all logger.info() calls
- [ ] Review error logging (may include stack traces with sensitive data)
- [ ] Check for logging in SSH connection code
- [ ] Check for logging in file reading code
- [ ] Check for logging in config updates

**Effort:** Medium (3-4 hours)  
**Impact:** Low (prevents information leakage)

---

## Implementation Roadmap

### Phase 1: Quick Wins (Week 1)
- ✅ Complete security audit (done)
- 🔴 Harden config file permissions
- 🟡 Add "Don't Remember" option for SSH

### Phase 2: Core Security (Week 2-3)
- 🔴 Implement SSH credential encryption
- 🟡 Add security audit logging

### Phase 3: Polish (Week 4)
- 🟡 Add Content Security Policy
- 🟢 Audit log statements
- 🟢 Secure memory handling (if time permits)

---

## Testing & Validation

### Security Testing Checklist

#### Path Validation Tests
- [ ] Attempt to access `/etc/passwd` → Blocked
- [ ] Attempt to access `~/.ssh/id_rsa` → Blocked
- [ ] Attempt path traversal `../../etc/shadow` → Blocked
- [ ] Attempt symlink escape to sensitive file → Blocked
- [ ] Verify allowed paths work: `~/.claude/`, project root

#### Command Injection Tests
- [ ] Try shell metacharacters in editor name → Safe (execFile)
- [ ] Try command injection in config paths → Safe (validated)

#### Network Security Tests
- [ ] Verify HTTP server only binds to 127.0.0.1
- [ ] Verify CORS rejects non-localhost origins
- [ ] Verify URL validation blocks dangerous protocols

#### Credential Security Tests
- [ ] Verify passwords not stored in config
- [ ] Verify SSH keys properly protected (after encryption impl)
- [ ] Verify config file has 600 permissions

---

## Security Best Practices for Contributors

### Code Review Checklist

When reviewing PRs, check for:

1. **Path Operations**
   - [ ] All file paths validated using `validateFilePath()` or `validateOpenPath()`
   - [ ] No direct `fs.readFile()` without validation
   - [ ] No `path.join()` with user input without validation

2. **Command Execution**
   - [ ] Use `execFile()`, never `exec()` or `{ shell: true }`
   - [ ] All command arguments properly escaped/validated
   - [ ] Timeouts set on all process spawns

3. **User Input**
   - [ ] All IPC handler inputs validated
   - [ ] Type checking before use
   - [ ] Regex patterns validated before compilation

4. **Sensitive Data**
   - [ ] No credentials in logs
   - [ ] No sensitive data in error messages
   - [ ] Proper encryption for stored secrets

5. **Network Operations**
   - [ ] No binding to 0.0.0.0 (external interfaces)
   - [ ] URL validation for external links
   - [ ] CORS properly configured

---

## Contact & Questions

For security concerns or questions about these recommendations:

1. Open a private security advisory on GitHub
2. Reference this document
3. Tag with "security" label

**Do not** open public issues for undisclosed security vulnerabilities.

---

**Document Version:** 1.0  
**Last Updated:** February 13, 2026  
**Next Review:** Before 1.0 release
