// Secure hashing using bcrypt library
import * as bcrypt from "bcrypt";

public class AuthService {
    private readonly saltRounds: number = 12;

    public async hashUserPassword(password: string): Promise<string> {
        // Using bcrypt to securely hash passwords with salt
        const hash = await bcrypt.hash(password, this.saltRounds);
        return hash;
    }
}
