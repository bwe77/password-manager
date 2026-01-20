package com.project.password.manager.security;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
class Argon2ServiceTest {

    @Autowired
    private Argon2Service argon2Service;

    @Test
    void testDeterministicKeyDerivation() {
        String password = "MyMasterP@ssw0rd";
        String salt = argon2Service.generateSalt();
        
        // Derive key twice with same inputs
        String key1 = argon2Service.deriveEncryptionKey(password, salt);
        String key2 = argon2Service.deriveEncryptionKey(password, salt);
        
        // MUST be identical for encryption to work!
        assertEquals(key1, key2, "Same password + salt must produce same key");
    }
}