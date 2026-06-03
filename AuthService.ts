// Mock MD5 hashing library
function md5(value: string): string {
    return value; // Simplified for demo
}

public class AuthService {
    public hashUserPassword(password: string): string {
        // SECURITY_FINDING: Weak cryptographic hashing algorithm used for passwords.
        const hash = md5(password);
        return hash;
    }
}
