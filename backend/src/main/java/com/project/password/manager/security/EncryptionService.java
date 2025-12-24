package com.project.password.manager.security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.SecureRandom;
import java.util.Base64;

import org.springframework.stereotype.Service;

/**
 * Encryption Service for Password Manager
 * 
 * Uses AES-256-GCM for authenticated encryption.
 * 
 * Key Features:
 * - AES-256: Industry standard, unbreakable with current technology
 * - GCM Mode: Provides both confidentiality and authenticity
 * - Unique IV per encryption: Same plaintext → different ciphertext
 * - Authenticated: Detects tampering attempts
 * 
 * Security Properties:
 * - Encryption key derived from user's master password (never stored)
 * - Each password has unique IV (prevents pattern analysis)
 * - GCM authentication tag prevents tampering
 * - Zero-knowledge architecture (server never sees plaintext)
 */

@Service
public class EncryptionService {
    // AES-256-GCM config
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int AES_KEY_SIZE = 256; // bits
    private static final int GCM_IV_LENGTH = 12; // bytes
    private static final int GCM_TAG_LENGTH = 16; // bytes

    private final SecureRandom secureRandom;

    public EncryptionService() {
        this.secureRandom = new SecureRandom();
    }

    /**
     * Encrypt plaintext password using AES-256-GCM
     * 
     * Process:
     * 1. Generate random IV (12 bytes)
     * 2. Derive encryption key from user's master password
     * 3. Encrypt password with AES-256-GCM
     * 4. Return IV and ciphertext (both needed for decryption)
     * 
     * @param plaintext The password to encrypt
     * @param encryptionKeyBase64 Base64-encoded encryption key (from Argon2)
     * @return EncryptedData containing IV and ciphertext
     * @throws RuntimeException if encryption fails
     */
    public EncryptedData encrypt(String plaintext, String encryptionKeyBase64) {
        try {
            // Generate random IV (Initialization Vector)
            byte[] iv = generateIV();
            
            // Decode the encryption key from Base64
            byte[] keyBytes = Base64.getDecoder().decode(encryptionKeyBase64);
            SecretKey key = new SecretKeySpec(keyBytes, "AES");
            
            // Initialize cipher for encryption
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
            
            // Encrypt the plaintext
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));
            
            // Encode IV and ciphertext to Base64 for storage
            String ivBase64 = Base64.getEncoder().encodeToString(iv);
            String ciphertextBase64 = Base64.getEncoder().encodeToString(ciphertext);
            
            return new EncryptedData(ivBase64, ciphertextBase64);
            
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    /**
     * Decrypt ciphertext using AES-256-GCM
     * 
     * Process:
     * 1. Decode IV and ciphertext from Base64
     * 2. Derive encryption key from user's master password
     * 3. Decrypt using AES-256-GCM
     * 4. Verify authentication tag (GCM automatically checks)
     * 5. Return plaintext password
     * 
     * @param ciphertextBase64 Base64-encoded ciphertext
     * @param ivBase64 Base64-encoded IV
     * @param encryptionKeyBase64 Base64-encoded encryption key
     * @return Decrypted plaintext password
     * @throws RuntimeException if decryption fails or data was tampered with
     */
    public String decrypt(String ciphertextBase64, String ivBase64, String encryptionBase64){
        try {
            //decode from base64
            byte[] ciphertext = Base64.getDecoder().decode(ciphertextBase64);
            byte[] iv = Base64.getDecoder().decode(ivBase64);
            byte[] keyBytes = Base64.getDecoder().decode(encryptionBase64);

            //Create secret key
            SecretKey key = new SecretKeySpec(keyBytes, "AES");

            // Initialize cipher for encryption
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

            //decrypt
            byte[] plaintext = cipher.doFinal(ciphertext);

            return new String(plaintext, "UTF-8");

        } catch (Exception e) {
            throw new RuntimeException("Decryption failed - data may be corrupted or tampered with", e);
        }
    }

    /**
     * Generate a cryptographically secure random IV (Initialization Vector)
     * 
     * Each encryption operation MUST use a unique IV to maintain security.
     * Even encrypting the same password twice should produce different ciphertexts.
     * 
     * @return 12-byte random IV
     */
    public byte[] generateIV() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        return iv;
    }

    /**
     * Generate a secure random encryption key (for testing purposes)
     * 
     * In production, encryption keys are derived from user's master password
     * using Argon2. This method is useful for testing.
     * 
     * @return Base64-encoded 256-bit AES key
     */
    public String generateRandomKey(){
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(AES_KEY_SIZE);
            SecretKey secretKey = keyGen.generateKey();
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (Exception e) {
            throw new RuntimeException("Key generation failed", e);
        }
    }

    /**
     * Re-encrypt data with a new key
     * 
     * Use case: User changes master password, need to re-encrypt all passwords
     * 
     * @param ciphertextBase64 Current ciphertext
     * @param ivBase64 Current IV
     * @param oldKeyBase64 Old encryption key
     * @param newKeyBase64 New encryption key
     * @return New EncryptedData with new ciphertext and IV
     */
    public EncryptedData reEncrypt(
            String ciphertextBase64,
            String ivBase64,
            String oldKeyBase64,
            String newKeyBase64
    ) {
        // Decrypt with old key
        String plaintext = decrypt(ciphertextBase64, ivBase64, oldKeyBase64);
        
        // Encrypt with new key (automatically generates new IV)
        return encrypt(plaintext, newKeyBase64);
    }

    /**
     * Data class to hold encrypted data
     * 
     * Both IV and ciphertext must be stored to decrypt later.
     * IV doesn't need to be secret, but must be unique per encryption.
     */
    public static class EncryptedData {
        private final String iv;
        private final String ciphertext;

        public EncryptedData(String iv, String ciphertext) {
            this.iv = iv;
            this.ciphertext = ciphertext;
        }

        public String getIv() {
            return iv;
        }

        public String getCiphertext() {
            return ciphertext;
        }
    }
    
}
