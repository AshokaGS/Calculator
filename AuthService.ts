class AuthService {
    public hashUserPassword(password: string): string {
        // Use a secure hashing algorithm instead of MD5
        // For demonstration, using a simple SHA-256 implementation
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        // Note: crypto.subtle.digest returns a Promise, so this method should be async
        throw new Error('Use async hashUserPassword method with crypto.subtle.digest for secure hashing');
    }
}

// Example of an async secure hash function
export async function hashUserPasswordAsync(password: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}
