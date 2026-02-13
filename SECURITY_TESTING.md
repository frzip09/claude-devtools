# Security Testing Guide for claude-devtools

This guide provides practical security testing procedures for validating the security controls in claude-devtools.

---

## Quick Test Commands

```bash
# Test config file permissions (Unix/Linux/macOS)
ls -la ~/.claude/claude-devtools-config.json
# Expected: -rw------- (600)

# Test config directory permissions (Unix/Linux/macOS)
ls -ld ~/.claude/
# Expected: drwx------ (700)

# Test that app is listening only on localhost
netstat -an | grep 3456
# Expected: 127.0.0.1:3456 (never 0.0.0.0:3456)

# Check for sensitive data in logs
grep -i "password\|secret\|privateKey" ~/.claude/logs/* 2>/dev/null
# Expected: No matches (or only "[REDACTED]" entries)
```

---

## 1. File System Security Tests

### 1.1 Path Validation Tests

**Test: Block access to system files**
```typescript
// Test in Electron DevTools console (main process)
const { validateFilePath } = require('./utils/pathValidation');

// Should all return { valid: false, error: '...' }
validateFilePath('/etc/passwd', null);
validateFilePath('/etc/shadow', null);
validateFilePath('C:\\Windows\\System32\\config\\SAM', null); // Windows
```

**Test: Block SSH keys**
```typescript
// Should all fail
validateFilePath('~/.ssh/id_rsa', null);
validateFilePath('~/.ssh/id_ed25519', null);
validateFilePath('~/.ssh/id_ecdsa', null);
validateFilePath('/home/user/.ssh/config', null);
```

**Test: Block cloud credentials**
```typescript
// Should all fail
validateFilePath('~/.aws/credentials', null);
validateFilePath('~/.azure/credentials.json', null);
validateFilePath('~/.config/gcloud/credentials.json', null);
validateFilePath('~/.kube/config', null);
```

**Test: Block .env files**
```typescript
// Should all fail
validateFilePath('~/.env', null);
validateFilePath('/project/.env.local', null);
validateFilePath('/any/path/.env.production', null);
```

**Test: Path traversal attempts**
```typescript
// Should all fail
validateFilePath('../../../etc/passwd', '/home/user/project');
validateFilePath('/home/user/project/../../.ssh/id_rsa', '/home/user/project');
validateFilePath('~/.claude/../../.ssh/id_rsa', null);
```

**Test: Symlink escape attempts**
```bash
# Create test symlink
cd ~/.claude
ln -s ~/.ssh symlink-to-ssh

# Test access via symlink (should fail)
# In app: attempt to access ~/.claude/symlink-to-ssh/id_rsa
```

**Test: Allowed paths work**
```typescript
// Should all succeed
validateFilePath('~/.claude/projects/test/session.jsonl', null);
validateFilePath('~/.claude/todos/session-123.json', null);
validateFilePath('/path/to/project/src/main.ts', '/path/to/project');
```

### 1.2 File Permission Tests

**Test: Config file permissions after creation**
```bash
# Delete existing config to test fresh creation
rm ~/.claude/claude-devtools-config.json

# Start the app (creates new config)
# Then check permissions:
ls -la ~/.claude/claude-devtools-config.json

# Expected output:
# -rw------- 1 username username 1234 Feb 13 10:00 claude-devtools-config.json

# Verify octal permissions
stat -c "%a" ~/.claude/claude-devtools-config.json  # Linux
stat -f "%OLp" ~/.claude/claude-devtools-config.json  # macOS
# Expected: 600
```

**Test: Permission repair on existing files**
```bash
# Create config with insecure permissions
chmod 644 ~/.claude/claude-devtools-config.json

# Start the app (should auto-repair permissions)
# Check logs for warning message about insecure permissions

# Verify permissions were fixed:
ls -la ~/.claude/claude-devtools-config.json
# Expected: -rw------- (600)
```

**Test: Directory permissions**
```bash
# Check .claude directory permissions
stat -c "%a" ~/.claude  # Linux
stat -f "%OLp" ~/.claude  # macOS
# Expected: 700 (drwx------)
```

---

## 2. Command Injection Tests

### 2.1 Editor Command Tests

**Test: Shell metacharacters in editor name (should be safe)**
```typescript
// Attempt to inject command via editor name
// The app uses execFile (not exec), so shell metacharacters won't work

// These should safely fail (editor not found) but NOT execute injected commands:
process.env.VISUAL = 'code; rm -rf ~/*';
process.env.EDITOR = 'vim && cat /etc/passwd';

// Try opening config - should fail to find editor but NOT execute injection
// Monitor system to ensure no files deleted, no /etc/passwd displayed
```

**Test: Path with special characters**
```typescript
// Test opening config at path with shell metacharacters
// Should be handled safely by execFile
const testPath = '/tmp/test; echo hacked > /tmp/hacked.txt; code';
// Opening this path should fail safely without creating /tmp/hacked.txt
```

**Manual Test:**
1. Set `EDITOR` env var to: `vim; touch /tmp/injected.txt; #`
2. Open app settings
3. Click "Open config in editor"
4. Check that `/tmp/injected.txt` was NOT created
5. Expected: Error about vim not found, no file injection

---

## 3. Network Security Tests

### 3.1 HTTP Server Binding Tests

**Test: Server binds only to localhost**
```bash
# Start the app with HTTP server enabled

# Check listening ports
netstat -an | grep 3456  # All platforms
lsof -i :3456  # macOS/Linux
ss -tlnp | grep 3456  # Linux

# Expected output should show:
# 127.0.0.1:3456 (or ::1:3456 for IPv6)
# 
# Should NEVER show:
# 0.0.0.0:3456 (would allow external connections)
```

**Test: Connections from external IP rejected**
```bash
# If you have a second machine on your network:
# From Machine A (running claude-devtools):
ifconfig | grep "inet "  # Note your local IP (e.g., 192.168.1.100)

# From Machine B (on same network):
curl http://192.168.1.100:3456
# Expected: Connection refused or timeout

# From Machine A (should work):
curl http://127.0.0.1:3456
# Expected: HTTP response (or 404 if route doesn't exist)
```

### 3.2 CORS Tests

**Test: CORS blocks non-localhost origins**
```bash
# Start HTTP server
# Try to access from browser with different origin

# Create test HTML file:
cat > /tmp/cors-test.html << 'EOF'
<!DOCTYPE html>
<html>
<body>
<script>
fetch('http://127.0.0.1:3456/api/projects')
  .then(r => r.json())
  .then(d => console.log('Success:', d))
  .catch(e => console.error('CORS blocked:', e));
</script>
</body>
</html>
EOF

# Serve from different port using Python:
cd /tmp && python3 -m http.server 8000

# Open http://localhost:8000/cors-test.html in browser
# Open DevTools console

# Expected: CORS error (blocked by CORS policy)
# The fetch should fail because origin (localhost:8000) doesn't match allowed origins
```

**Test: CORS allows same origin**
```html
<!-- Test from the actual app renderer -->
<script>
// This should work (same origin)
fetch('http://127.0.0.1:3456/api/projects')
  .then(r => r.json())
  .then(d => console.log('Success:', d));
</script>
```

### 3.3 URL Validation Tests

**Test: Block dangerous protocols**
```typescript
// In renderer process, try opening dangerous URLs:
window.electronAPI.openExternal('file:///etc/passwd');
// Expected: Error - "Only http, https, and mailto URLs are allowed"

window.electronAPI.openExternal('javascript:alert(1)');
// Expected: Same error

window.electronAPI.openExternal('data:text/html,<script>alert(1)</script>');
// Expected: Same error

// These should work:
window.electronAPI.openExternal('https://google.com');
window.electronAPI.openExternal('mailto:test@example.com');
```

---

## 4. SSH Security Tests

### 4.1 Credential Storage Tests

**Test: Passwords not stored**
```typescript
// Connect with password authentication
const config = {
  host: 'example.com',
  port: 22,
  username: 'testuser',
  authMethod: 'password',
  password: 'super-secret-password'
};

await window.electronAPI.ssh.connect(config);

// Check config file
cat ~/.claude/claude-devtools-config.json | grep -i password
// Expected: No matches (password should NOT be in config file)
```

**Test: Connection details are stored**
```bash
# After connecting via SSH, check config:
cat ~/.claude/claude-devtools-config.json | jq '.ssh.lastConnection'

# Expected: Should contain host, port, username, authMethod
# Should NOT contain: password
```

**Test: Private key paths stored (but not key content)**
```typescript
// Connect with private key
const config = {
  host: 'example.com',
  port: 22,
  username: 'testuser',
  authMethod: 'privateKey',
  privateKeyPath: '/home/user/.ssh/custom_key'
};

await window.electronAPI.ssh.connect(config);

// Check config file
cat ~/.claude/claude-devtools-config.json | jq '.ssh.lastConnection.privateKeyPath'
// Expected: "/home/user/.ssh/custom_key" (path only, not key content)

# Verify the actual private key content is NOT in config:
cat ~/.claude/claude-devtools-config.json | grep "BEGIN.*PRIVATE KEY"
# Expected: No matches
```

### 4.2 SSH Connection Tests

**Test: SSH agent discovery**
```bash
# Test 1: With SSH_AUTH_SOCK set
export SSH_AUTH_SOCK=/tmp/ssh-agent.sock
# Start app, attempt SSH connection with authMethod: 'agent'
# Should use the socket path from env var

# Test 2: Without SSH_AUTH_SOCK (macOS)
unset SSH_AUTH_SOCK
# Start app, attempt SSH connection with authMethod: 'agent'
# Should fall back to launchctl or known paths
```

**Test: Auto authentication fallback**
```typescript
// Test 'auto' auth method
const config = {
  host: 'example.com',
  port: 22,
  username: 'testuser',
  authMethod: 'auto'
};

// Should try in order:
// 1. SSH config identity file
// 2. SSH agent
// 3. Default keys (id_ed25519, id_rsa, id_ecdsa)
```

---

## 5. Input Validation Tests

### 5.1 IPC Input Validation Tests

**Test: Config update validation**
```typescript
// In renderer console

// Invalid: wrong type
await window.electronAPI.config.update('notifications', { enabled: 'yes' });
// Expected: Error about type validation

// Invalid: invalid regex
await window.electronAPI.config.addIgnoreRegex('(unclosed group');
// Expected: Error about invalid regex

// Invalid: negative snooze
await window.electronAPI.config.snooze(-5);
// Expected: Error about invalid duration

// Invalid: too long snooze
await window.electronAPI.config.snooze(9999999);
// Expected: Error about maximum duration

// Valid: proper values
await window.electronAPI.config.snooze(30);
// Expected: Success
```

### 5.2 Path Input Validation

**Test: Reject relative paths**
```typescript
await window.electronAPI.validatePath('./relative/path', '/project/root');
// Expected: Validation failure (must be absolute)

await window.electronAPI.validatePath('../../../etc/passwd', '/project/root');
// Expected: Validation failure (traversal attempt)
```

---

## 6. XSS Prevention Tests

### 6.1 Content Rendering Tests

**Test: Markdown rendering doesn't execute scripts**
```typescript
// Create a session with malicious markdown content
const maliciousMarkdown = `
# Test
<script>alert('XSS')</script>
<img src=x onerror="alert('XSS')">
[Click me](javascript:alert('XSS'))
`;

// Render in chat UI
// Expected: 
// - <script> tags removed or escaped
// - onerror not executed
// - javascript: links blocked or made safe
// - No alert boxes appear
```

**Test: File path rendering doesn't execute HTML**
```typescript
// Test with HTML in file paths
const maliciousPath = '</code><script>alert("XSS")</script><code>';

// Expected: Rendered as plain text, script not executed
```

---

## 7. Electron Security Tests

### 7.1 Context Isolation Tests

**Test: Renderer cannot access Node.js APIs**
```javascript
// In Electron renderer DevTools console:
typeof require
// Expected: "undefined" (not "function")

typeof process.versions.node
// Expected: "undefined"

typeof __dirname
// Expected: "undefined"

typeof Buffer
// Expected: "undefined"
```

**Test: Renderer can only access exposed API**
```javascript
// In renderer console:
typeof window.electronAPI
// Expected: "object"

typeof window.electronAPI.config.get
// Expected: "function"

// Try to access internal APIs (should be undefined):
typeof window.electronAPI.ipcRenderer
// Expected: "undefined"

typeof window.require
// Expected: "undefined"
```

### 7.2 Node Integration Tests

**Test: Node integration disabled**
```javascript
// In renderer console:
window.process
// Expected: undefined (or minimal safe properties)

// Try to access Node APIs
typeof require
// Expected: "undefined"

typeof module.exports
// Expected: undefined or error (module not defined)
```

---

## 8. Build Security Tests

### 8.1 Code Signing Verification (macOS)

```bash
# After building the app:
codesign -vvv --deep --strict /path/to/claude-devtools.app
# Expected: No errors, "satisfies its Designated Requirement"

# Check hardened runtime:
codesign -d --entitlements - /path/to/claude-devtools.app
# Expected: Should show entitlements including hardened runtime

# Verify notarization:
spctl -a -vvv -t install /path/to/claude-devtools.app
# Expected: "accepted" and "notarized"
```

### 8.2 ASAR Integrity

```bash
# Extract ASAR to inspect contents
npx asar extract app.asar /tmp/extracted

# Check for sensitive data in bundle:
grep -r "password\|secret\|api.?key" /tmp/extracted/
# Expected: No hardcoded secrets

# Check for source maps (should not be in production):
find /tmp/extracted -name "*.map"
# Expected: No .map files in production build
```

---

## 9. Automated Security Testing

### 9.1 Run Security Scanners

```bash
# NPM audit
npm audit
npm audit --production

# Check for known vulnerabilities
npx snyk test

# Run linter with security rules
npm run lint

# Check for secrets in code
npm install -g trufflehog
trufflehog filesystem . --json --fail
```

### 9.2 Static Analysis

```bash
# TypeScript compiler in strict mode
npm run typecheck

# ESLint with security plugin (already in package.json)
npm run lint

# Check for common security issues
npx eslint . --ext .ts,.tsx --max-warnings 0
```

---

## 10. Regression Testing

After any security fix, re-run ALL tests in this guide to ensure:
1. The vulnerability is fixed
2. No new vulnerabilities were introduced
3. Legitimate functionality still works

### Security Test Checklist

- [ ] Path validation tests pass
- [ ] Command injection tests pass
- [ ] Network security tests pass
- [ ] SSH credential tests pass
- [ ] Input validation tests pass
- [ ] XSS prevention tests pass
- [ ] Electron security tests pass
- [ ] File permissions correct (Unix: 600)
- [ ] No sensitive data in logs
- [ ] No hardcoded secrets in code
- [ ] Code signing valid (macOS)
- [ ] All automated scanners pass

---

## 11. Penetration Testing

For a comprehensive security assessment, consider hiring a professional penetration testing firm to:

1. **Application Security Review**
   - Full source code audit
   - Dependency vulnerability analysis
   - Configuration review

2. **Runtime Testing**
   - Fuzzing IPC handlers
   - Memory safety testing
   - Privilege escalation attempts

3. **Infrastructure Testing**
   - Network security assessment
   - SSH connection security
   - File system security

---

## 12. Continuous Security Monitoring

### Automated Checks (CI/CD)

Add to GitHub Actions workflow:
```yaml
- name: Security Audit
  run: |
    npm audit --audit-level=moderate
    npm run lint
    npm run typecheck
```

### Regular Reviews

- **Weekly:** Check npm audit output
- **Monthly:** Review security advisories for dependencies
- **Quarterly:** Run full security test suite
- **Annually:** External security audit

---

## Reporting Security Issues

If you find a security vulnerability:

1. **DO NOT** open a public GitHub issue
2. **DO** use GitHub Security Advisories (private reporting)
3. **DO** include:
   - Vulnerability description
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if applicable)

---

**Document Version:** 1.0  
**Last Updated:** February 13, 2026  
**Next Review:** Before 1.0 release
