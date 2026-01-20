package com.project.password.manager.security;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Custom Argon2 service for deriving encryption keys from master passwords.
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

    private final Argon2 argon2;
    private final SecureRandom secureRandom;

    public Argon2Service() {
        // Use Argon2id (hybrid of Argon2i and Argon2d)
        this.argon2 = Argon2Factory.create(
            Argon2Factory.Argon2Types.ARGON2id,
            SALT_LENGTH,
            HASH_LENGTH
        );
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
            byte[] salt = Base64.getDecoder().decode(saltBase64);
            
            // Use hashRaw() to get raw bytes instead of encoded string
            // This ensures deterministic output: same password + salt = same key
            byte[] hash = argon2.hashRaw(
                ITERATIONS,
                MEMORY_KB,
                PARALLELISM,
                masterPassword.toCharArray(),
                StandardCharsets.UTF_8,
                salt
            );
            
            // Hash is already 32 bytes (256 bits) - perfect for AES-256
            return Base64.getEncoder().encodeToString(hash);
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive encryption key", e);
        } finally {
            // Wipe sensitive data from memory
            argon2.wipeArray(masterPassword.toCharArray());
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
            
            // Combine password with purpose to create unique derivation
            String combinedPassword = masterPassword + ":" + purpose;
            
            byte[] hash = argon2.hashRaw(
                ITERATIONS,
                MEMORY_KB,
                PARALLELISM,
                combinedPassword.toCharArray(),
                StandardCharsets.UTF_8,
                salt
            );
            
            return Base64.getEncoder().encodeToString(hash);
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive secondary key", e);
        } finally {
            argon2.wipeArray(masterPassword.toCharArray());
        }
    }

    /**
     * Hash a password for verification (not for key derivation).
     * This is useful for additional password checks.
     * 
     * @param password The password to hash
     * @return Argon2 hash string (encoded with parameters)
     */
    public String hashPassword(String password) {
        try {
            return argon2.hash(ITERATIONS, MEMORY_KB, PARALLELISM, password.toCharArray());
        } finally {
            argon2.wipeArray(password.toCharArray());
        }
    }

    /**
     * Verify a password against an Argon2 hash.
     * 
     * @param hash The Argon2 hash string
     * @param password The password to verify
     * @return true if password matches
     */
    public boolean verifyPassword(String hash, String password) {
        try {
            return argon2.verify(hash, password.toCharArray());
        } finally {
            argon2.wipeArray(password.toCharArray());
        }
    }

    /**
     * Clean up sensitive data from memory.
     * Call this when done with sensitive operations.
     */
    public void cleanup() {
        // Argon2 library handles memory cleanup automatically via wipeArray()
        // This method exists for future enhancements if needed
    }
}