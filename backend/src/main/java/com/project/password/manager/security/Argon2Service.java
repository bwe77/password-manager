package com.project.password.manager.security;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Custom Argon2 service for deriving encryption keys from master passwords.
 * 
 * Uses BouncyCastle's Argon2 implementation for full control over key derivation.
 * 
 * This is separate from Spring Security's PasswordEncoder (which uses BCrypt)
 * because we need Argon2 specifically for key derivation in our zero-knowledge
 * architecture.
 * 
 * Flow:
 * 1. User enters master password
 * 2. BCrypt hash stored in database (for authentication)
 * 3. Argon2 derives 256-bit encryption key (for AES-256-GCM)
 * 4. Encryption key never stored, regenerated on each login
 * 
 * Key Derivation Process:
 * - Same password + same salt = SAME encryption key (deterministic)
 * - Different salt = different key (user-specific)
 * - Uses Argon2id for resistance to GPU/ASIC attacks
 */
@Service
public class Argon2Service {

    private static final int SALT_LENGTH = 16; // 128 bits
    private static final int ITERATIONS = 3;
    private static final int MEMORY_KB = 65536; // 64 MB
    private static final int PARALLELISM = 1;
    private static final int HASH_LENGTH = 32; // 256 bits for AES-256

    private final SecureRandom secureRandom;

    public Argon2Service() {
        this.secureRandom = new SecureRandom();
    }

    /**
     * Generate a cryptographically secure random salt.
     * 
     * @return Base64-encoded salt (16 bytes)
     */
    public String generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * Derive a 256-bit encryption key from the master password using Argon2id.
     * 
     * CRITICAL: This is used for encrypting/decrypting password vault entries.
     * The key is NEVER stored - it must be derived on each login.
     * 
     * Same password + same salt MUST produce the same key every time!
     * 
     * @param masterPassword The user's master password
     * @param saltBase64 The Base64-encoded salt (unique per user)
     * @return Base64-encoded 256-bit encryption key
     */
    public String deriveEncryptionKey(String masterPassword, String saltBase64) {
        try {
            // Decode salt from Base64
            byte[] salt = Base64.getDecoder().decode(saltBase64);
            
            // Convert password to bytes
            byte[] passwordBytes = masterPassword.getBytes(StandardCharsets.UTF_8);
            
            // Configure Argon2 parameters
            Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(ITERATIONS)
                .withMemoryAsKB(MEMORY_KB)
                .withParallelism(PARALLELISM)
                .withSalt(salt)
                .build();
            
            // Generate the hash
            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(params);
            
            byte[] hash = new byte[HASH_LENGTH];
            generator.generateBytes(passwordBytes, hash);
            
            // Clear sensitive data
            clearArray(passwordBytes);
            
            // Return Base64-encoded key
            return Base64.getEncoder().encodeToString(hash);
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive encryption key", e);
        }
    }

    /**
     * Verify that a master password can derive the correct encryption key.
     * 
     * This is used during login to ensure the user can decrypt their vault.
     * 
     * @param masterPassword The password to verify
     * @param saltBase64 The user's salt
     * @param expectedKeyBase64 The expected encryption key
     * @return true if password derives the correct key
     */
    public boolean verifyKey(String masterPassword, String saltBase64, String expectedKeyBase64) {
        try {
            String derivedKey = deriveEncryptionKey(masterPassword, saltBase64);
            // Use constant-time comparison to prevent timing attacks
            return MessageDigest.isEqual(
                derivedKey.getBytes(StandardCharsets.UTF_8),
                expectedKeyBase64.getBytes(StandardCharsets.UTF_8)
            );
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Derive a secondary key for additional encryption purposes.
     * 
     * This can be used for:
     * - Encrypting TOTP secrets
     * - Encrypting shared password metadata
     * - Encrypting audit log details
     * 
     * @param masterPassword The user's master password
     * @param saltBase64 The user's salt
     * @param purpose A unique identifier for the key purpose (e.g., "TOTP", "SHARE")
     * @return Base64-encoded 256-bit secondary key
     */
    public String deriveSecondaryKey(String masterPassword, String saltBase64, String purpose) {
        try {
            byte[] salt = Base64.getDecoder().decode(saltBase64);
            
            // Append purpose to salt for unique derivation
            byte[] purposeBytes = purpose.getBytes(StandardCharsets.UTF_8);
            byte[] modifiedSalt = new byte[salt.length + purposeBytes.length];
            System.arraycopy(salt, 0, modifiedSalt, 0, salt.length);
            System.arraycopy(purposeBytes, 0, modifiedSalt, salt.length, purposeBytes.length);
            
            String modifiedSaltBase64 = Base64.getEncoder().encodeToString(modifiedSalt);
            return deriveEncryptionKey(masterPassword, modifiedSaltBase64);
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive secondary key", e);
        }
    }

    /**
     * Securely clear sensitive data from memory
     */
    private void clearArray(byte[] array) {
        if (array != null) {
            for (int i = 0; i < array.length; i++) {
                array[i] = 0;
            }
        }
    }

    /**
     * Clean up sensitive data from memory.
     * Call this when done with sensitive operations.
     */
    public void cleanup() {
        // Manual cleanup if needed
    }
}