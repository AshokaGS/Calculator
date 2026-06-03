// Secure hashing using bcrypt
import * as bcrypt from "bcrypt";

public class AuthService {
    private readonly saltRounds = 12;

    public async hashUserPassword(password: string): Promise<string> {
        // Use bcrypt to securely hash passwords with salt
        const hash = await bcrypt.hash(password, this.saltRounds);
        return hash;
    }
}
