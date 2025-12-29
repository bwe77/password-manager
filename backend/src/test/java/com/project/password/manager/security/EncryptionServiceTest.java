package com.project.password.manager.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for EncryptionService
 * 
 * Location: backend/src/test/java/com/project/password/manager/security/EncryptionServiceTest.java
 * 
 * Run with: mvn test
 * Or in IDE: Right-click and "Run Tests"
 */
class EncryptionServiceTest {

    private EncryptionService encryptionService;
    private Argon2Service argon2Service;
    private String encryptionKey;

    @BeforeEach
    void setUp() {
        // Initialize services before each test
        encryptionService = new EncryptionService();
        argon2Service = new Argon2Service();
        
        // Generate a test encryption key
        String masterPassword = "TestMasterP@ssw0rd123!";
        String salt = argon2Service.generateSalt();
        encryptionKey = argon2Service.deriveEncryptionKey(masterPassword, salt);
    }

    @Test
    @DisplayName("Should encrypt and decrypt password correctly")
    void testEncryptDecrypt() {
        // Given
        String originalPassword = "MySecurePassword123!";

        // When
        EncryptionService.EncryptedData encrypted = encryptionService.encrypt(originalPassword, encryptionKey);
        String decrypted = encryptionService.decrypt(encrypted.getCiphertext(), encrypted.getIv(), encryptionKey);

        // Then
        assertNotNull(encrypted.getCiphertext(), "Ciphertext should not be null");
        assertNotNull(encrypted.getIv(), "IV should not be null");
        assertEquals(originalPassword, decrypted, "Decrypted password should match original");
    }

    @Test
    @DisplayName("Should produce different ciphertext for same plaintext")
    void testUniqueCiphertext() {
        // Given
        String password = "SamePassword123!";

        // When
        EncryptionService.EncryptedData encrypted1 = encryptionService.encrypt(password, encryptionKey);
        EncryptionService.EncryptedData encrypted2 = encryptionService.encrypt(password, encryptionKey);

        // Then
        assertNotEquals(encrypted1.getCiphertext(), encrypted2.getCiphertext(), 
            "Same password should produce different ciphertext (unique IV)");
        assertNotEquals(encrypted1.getIv(), encrypted2.getIv(), 
            "Each encryption should have unique IV");
    }

    @Test
    @DisplayName("Should generate unique IV for each encryption")
    void testUniqueIV() {
        // When
        byte[] iv1 = encryptionService.generateIV();
        byte[] iv2 = encryptionService.generateIV();

        // Then
        assertNotNull(iv1);
        assertNotNull(iv2);
        assertEquals(12, iv1.length, "IV should be 12 bytes (96 bits) for GCM");
        assertEquals(12, iv2.length, "IV should be 12 bytes (96 bits) for GCM");
        assertFalse(java.util.Arrays.equals(iv1, iv2), "IVs should be unique");
    }

    @Test
    @DisplayName("Should throw exception when decrypting with wrong key")
    void testDecryptWithWrongKey() {
        // Given
        String password = "TestPassword123!";
        EncryptionService.EncryptedData encrypted = encryptionService.encrypt(password, encryptionKey);
        
        // Generate a different key
        String wrongKey = encryptionService.generateRandomKey();

        // When & Then
        assertThrows(RuntimeException.class, () -> {
            encryptionService.decrypt(encrypted.getCiphertext(), encrypted.getIv(), wrongKey);
        }, "Decryption with wrong key should throw exception");
    }

    @Test
    @DisplayName("Should throw exception when decrypting tampered data")
    void testDecryptTamperedData() {
        // Given
        String password = "TestPassword123!";
        EncryptionService.EncryptedData encrypted = encryptionService.encrypt(password, encryptionKey);
        
        // Tamper with the ciphertext (change one character)
        String tamperedCiphertext = encrypted.getCiphertext().substring(0, encrypted.getCiphertext().length() - 1) + "X";

        // When & Then
        assertThrows(RuntimeException.class, () -> {
            encryptionService.decrypt(tamperedCiphertext, encrypted.getIv(), encryptionKey);
        }, "Decryption of tampered data should throw exception (GCM authentication failure)");
    }

    @Test
    @DisplayName("Should encrypt and decrypt empty string")
    void testEmptyString() {
        // Given
        String emptyPassword = "";

        // When
        EncryptionService.EncryptedData encrypted = encryptionService.encrypt(emptyPassword, encryptionKey);
        String decrypted = encryptionService.decrypt(encrypted.getCiphertext(), encrypted.getIv(), encryptionKey);

        // Then
        assertEquals(emptyPassword, decrypted, "Should handle empty strings");
    }

    @Test
    @DisplayName("Should encrypt and decrypt unicode characters")
    void testUnicodeCharacters() {
        // Given
        String unicodePassword = "P@ssw0rd_日本語_🔐_Ñoño";

        // When
        EncryptionService.EncryptedData encrypted = encryptionService.encrypt(unicodePassword, encryptionKey);
        String decrypted = encryptionService.decrypt(encrypted.getCiphertext(), encrypted.getIv(), encryptionKey);

        // Then
        assertEquals(unicodePassword, decrypted, "Should handle unicode characters correctly");
    }

    @Test
    @DisplayName("Should encrypt and decrypt very long passwords")
    void testLongPassword() {
        // Given
        String longPassword = "a".repeat(1000); // 1000 character password

        // When
        EncryptionService.EncryptedData encrypted = encryptionService.encrypt(longPassword, encryptionKey);
        String decrypted = encryptionService.decrypt(encrypted.getCiphertext(), encrypted.getIv(), encryptionKey);

        // Then
        assertEquals(longPassword, decrypted, "Should handle long passwords");
    }

    @Test
    @DisplayName("Should re-encrypt data with new key successfully")
    void testReEncrypt() {
        // Given
        String password = "OriginalPassword123!";
        EncryptionService.EncryptedData encrypted = encryptionService.encrypt(password, encryptionKey);
        
        // Generate new key
        String newKey = encryptionService.generateRandomKey();

        // When
        EncryptionService.EncryptedData reEncrypted = encryptionService.reEncrypt(
            encrypted.getCiphertext(),
            encrypted.getIv(),
            encryptionKey,
            newKey
        );

        // Decrypt with new key
        String decrypted = encryptionService.decrypt(reEncrypted.getCiphertext(), reEncrypted.getIv(), newKey);

        // Then
        assertEquals(password, decrypted, "Re-encrypted password should match original");
        assertNotEquals(encrypted.getCiphertext(), reEncrypted.getCiphertext(), 
            "Re-encrypted ciphertext should be different");
    }

    @Test
    @DisplayName("Should generate valid random encryption key")
    void testGenerateRandomKey() {
        // When
        String key1 = encryptionService.generateRandomKey();
        String key2 = encryptionService.generateRandomKey();

        // Then
        assertNotNull(key1);
        assertNotNull(key2);
        assertNotEquals(key1, key2, "Generated keys should be unique");
        
        // Test that generated key can be used for encryption
        String testPassword = "TestPassword123!";
        EncryptionService.EncryptedData encrypted = encryptionService.encrypt(testPassword, key1);
        String decrypted = encryptionService.decrypt(encrypted.getCiphertext(), encrypted.getIv(), key1);
        assertEquals(testPassword, decrypted, "Generated key should work for encryption/decryption");
    }
}