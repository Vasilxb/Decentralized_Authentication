package da.decentralized_authentication.Util;

import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

@Component
public class PasswordUtil {

    private static final int HASH_ITERATIONS = 10_000;

    public String generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    public String hash(String plain, String salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] result = (plain + salt).getBytes("UTF-8");
            for (int i = 0; i < HASH_ITERATIONS; i++) {
                result = digest.digest(result);
            }
            StringBuilder sb = new StringBuilder();
            for (byte b : result) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("Хеширањето не успеа", e);
        }
    }

    public boolean matches(String plain, String salt, String expectedHash) {
        return hash(plain, salt).equals(expectedHash);
    }
}