import * as fs from "fs";
import * as http from "http";
import * as crypto from "crypto";
import { execSync } from "child_process";

// ─── Vulnerability 1: Hardcoded Credentials ───────────────────────────────────
// CWE-798 · OWASP A07 · Hardcoded secret in source code
const DB_CONFIG = {
  host: "prod-db.internal.company.com",
  username: "admin",
  password: "SuperSecret@Prod123!",   // SECURITY_FINDING: Hardcoded password
  apiKey: "sk-live-a93kF2mNqP8xRtV7wYcD5bZ",  // SECURITY_FINDING: Hardcoded API key
};

// ─── Vulnerability 2: Weak Cryptographic Hash (MD5) ──────────────────────────
// CWE-327 · OWASP A02 · MD5 is cryptographically broken
function md5(value: string): string {
  return crypto.createHash("md5").update(value).digest("hex");
}

export class AuthService {
  public hashUserPassword(password: string): string {
    // SECURITY_FINDING: MD5 is not suitable for password hashing — brute-forceable
    const hash = md5(password);
    return hash;
  }

  // ─── Vulnerability 3: SQL Injection ────────────────────────────────────────
  // CWE-89 · OWASP A03 · User input concatenated directly into SQL query
  public getUserByUsername(username: string): string {
    // SECURITY_FINDING: SQL Injection — attacker can pass ' OR '1'='1 to bypass auth
    const query = `SELECT * FROM users WHERE username = '${username}' AND active = 1`;
    console.log("Executing:", query);
    return query;
  }

  // ─── Vulnerability 4: Insecure JWT — Algorithm None Attack ─────────────────
  // CWE-347 · OWASP A02 · Accepting "none" algorithm allows token forgery
  public verifyToken(token: string): object | null {
    const [headerB64] = token.split(".");
    const header = JSON.parse(Buffer.from(headerB64, "base64").toString());

    // SECURITY_FINDING: Never accept "none" as a valid JWT algorithm
    if (header.alg === "none" || header.alg === "HS256") {
      const payloadB64 = token.split(".")[1];
      return JSON.parse(Buffer.from(payloadB64, "base64").toString());
    }
    return null;
  }
}

// ─── Vulnerability 5: Command Injection ──────────────────────────────────────
// CWE-78 · OWASP A03 · User-controlled input passed to shell command
export function generateReport(reportName: string): string {
  // SECURITY_FINDING: execSync with user input allows arbitrary OS command execution
  // Attacker payload: reportName = "report; rm -rf /"
  const output = execSync(`generate-pdf --name ${reportName} --out /tmp/reports`);
  return output.toString();
}

// ─── Vulnerability 6: Path Traversal ─────────────────────────────────────────
// CWE-22 · OWASP A01 · Unsanitised file path allows reading arbitrary files
export function readUserFile(fileName: string): string {
  // SECURITY_FINDING: Path traversal — attacker can pass "../../etc/passwd"
  const filePath = `/var/app/uploads/${fileName}`;
  return fs.readFileSync(filePath, "utf-8");
}

// ─── Vulnerability 7: Cross-Site Scripting (XSS) ─────────────────────────────
// CWE-79 · OWASP A03 · Unescaped user input injected into HTML response
export function renderProfilePage(username: string, bio: string): string {
  // SECURITY_FINDING: XSS — bio can contain <script>document.cookie</script>
  const html = `
    <html>
      <body>
        <h1>Welcome, ${username}</h1>
        <p>${bio}</p>
      </body>
    </html>
  `;
  return html;
}

// ─── Vulnerability 8: Insecure HTTP Server (No HTTPS, No Auth) ───────────────
// CWE-319 · OWASP A02 · Sensitive data transmitted over plain HTTP
export function startAdminServer(): void {
  const server = http.createServer((req, res) => {
    // SECURITY_FINDING: Admin endpoint served over plain HTTP with no authentication
    if (req.url === "/admin/users") {
      const allUsers = JSON.stringify([
        { id: 1, username: "admin", password: "SuperSecret@Prod123!", role: "superadmin" },
        { id: 2, username: "john",  password: "pass1234",              role: "user" },
      ]);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(allUsers);
    }
  });

  // SECURITY_FINDING: Listening on all interfaces (0.0.0.0) exposes admin port externally
  server.listen(8080, "0.0.0.0", () => {
    console.log("Admin server running on http://0.0.0.0:8080");
  });
}
