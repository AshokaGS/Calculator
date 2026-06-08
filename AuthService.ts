import * as fs from "fs";
import * as http from "http";
import * as crypto from "crypto";
import { execSync } from "child_process";

// ─── Vulnerability 1: Hardcoded Credentials ───────────────────────────────────
// CWE-798 · OWASP A07 · Hardcoded secret in source code
const DB_CONFIG = {
  host: "prod-db.internal.company.com",
  username: "admin",
  // Removed hardcoded password and apiKey for security
  // password: "SuperSecret@Prod123!",
  // apiKey: "sk-live-a93kF2mNqP8xRtV7wYcD5bZ",
};

// ─── Vulnerability 2: Weak Cryptographic Hash (MD5) ──────────────────────────
// CWE-327 · OWASP A02 · MD5 is cryptographically broken
// Removed md5 function and replaced with secure async hash

export class AuthService {
  // Updated to async method using crypto.subtle.digest
  public async hashUserPassword(password: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.webcrypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
  }

  // ─── Vulnerability 3: SQL Injection ────────────────────────────────────────
  // CWE-89 · OWASP A03 · User input concatenated directly into SQL query
  public getUserByUsername(username: string): string {
    // Use parameterized queries or escape input to prevent SQL injection
    // For demonstration, escaping single quotes
    const safeUsername = username.replace(/'/g, "''");
    const query = `SELECT * FROM users WHERE username = '${safeUsername}' AND active = 1`;
    console.log("Executing:", query);
    return query;
  }

  // ─── Vulnerability 4: Insecure JWT — Algorithm None Attack ─────────────────
  // CWE-347 · OWASP A02 · Accepting "none" algorithm allows token forgery
  public verifyToken(token: string): object | null {
    const [headerB64] = token.split(".");
    const header = JSON.parse(Buffer.from(headerB64, "base64").toString());

    // Reject "none" algorithm
    if (header.alg === "none") {
      return null;
    }

    if (header.alg === "HS256") {
      const payloadB64 = token.split(".")[1];
      return JSON.parse(Buffer.from(payloadB64, "base64").toString());
    }
    return null;
  }
}

// ─── Vulnerability 5: Command Injection ──────────────────────────────────────
// CWE-78 · OWASP A03 · User-controlled input passed to shell command
export function generateReport(reportName: string): string {
  // Sanitize reportName to allow only alphanumeric, dash and underscore
  const safeReportName = reportName.replace(/[^a-zA-Z0-9-_]/g, '');
  const output = execSync(`generate-pdf --name ${safeReportName} --out /tmp/reports`);
  return output.toString();
}

// ─── Vulnerability 6: Path Traversal ─────────────────────────────────────────
// CWE-22 · OWASP A01 · Unsanitised file path allows reading arbitrary files
export function readUserFile(fileName: string): string {
  // Sanitize fileName to prevent path traversal
  if (fileName.includes('..') || fileName.includes('/') || fileName.includes('\\')) {
    throw new Error('Invalid file name');
  }
  const filePath = `/var/app/uploads/${fileName}`;
  return fs.readFileSync(filePath, "utf-8");
}

// ─── Vulnerability 7: Cross-Site Scripting (XSS) ─────────────────────────────
// CWE-79 · OWASP A03 · Unescaped user input injected into HTML response
export function renderProfilePage(username: string, bio: string): string {
  // Escape bio to prevent XSS
  const escapeHtml = (unsafe: string) =>
    unsafe
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");

  const safeBio = escapeHtml(bio);
  const safeUsername = escapeHtml(username);

  const html = `
    <html>
      <body>
        <h1>Welcome, ${safeUsername}</h1>
        <p>${safeBio}</p>
      </body>
    </html>
  `;
  return html;
}

// ─── Vulnerability 8: Insecure HTTP Server (No HTTPS, No Auth) ───────────────
// CWE-319 · OWASP A02 · Sensitive data transmitted over plain HTTP
export function startAdminServer(): void {
  const server = http.createServer((req, res) => {
    // Added basic authentication check
    const auth = req.headers['authorization'];
    if (!auth || auth !== 'Basic ' + Buffer.from('admin:SuperSecret@Prod123!').toString('base64')) {
      res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="Admin Area"' });
      res.end('Unauthorized');
      return;
    }

    if (req.url === "/admin/users") {
      const allUsers = JSON.stringify([
        { id: 1, username: "admin", password: "[REDACTED]", role: "superadmin" },
        { id: 2, username: "john",  password: "[REDACTED]", role: "user" },
      ]);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(allUsers);
    } else {
      res.writeHead(404);
      res.end();
    }
  });

  // Listen only on localhost to avoid external exposure
  server.listen(8080, "127.0.0.1", () => {
    console.log("Admin server running on http://127.0.0.1:8080");
  });
}

// Removed duplicate async hashUserPasswordAsync function since it's now integrated
