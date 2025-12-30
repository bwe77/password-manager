package com.project.password.manager.services;

import com.project.password.manager.dto.response.BreachedPasswordInfo;
import com.project.password.manager.models.PasswordEntry;
import com.project.password.manager.models.User;
import com.project.password.manager.repo.PasswordEntryRepository;
import com.project.password.manager.repo.UserRepository;
import com.project.password.manager.security.Argon2Service;
import com.project.password.manager.security.EncryptionService;


import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;


@Service
public class BreachDetectionService {
    private final WebClient haveibeenpwnedClient;
    private final PasswordEntryRepository passwordEntryRepository;
    private final UserRepository userRepository;
    private final EncryptionService encryptionService;
    private final Argon2Service argon2Service;
    
    // checkPasswordBreach(String password) -> boolean
    // Uses k-anonymity: hash password with SHA-1, send first 5 chars
    // checkAllPasswords(Long userId) -> List<BreachedPasswordInfo>
    // scheduleBreachCheck() // @Scheduled for periodic checks

    public BreachDetectionService(WebClient haveIBeenPwnedWebClient, PasswordEntryRepository passwordEntryRepository, UserRepository userRepository, EncryptionService encryptionService, Argon2Service argon2Service) {
        this.haveibeenpwnedClient = haveIBeenPwnedWebClient;
        this.passwordEntryRepository = passwordEntryRepository;
        this.userRepository = userRepository;
        this.encryptionService = encryptionService;
        this.argon2Service = argon2Service;
    }

    /**
     * Check if a password has been breached using k-anonymity model
     * 
     * Process (k-anonymity for privacy):
     * 1. Hash password with SHA-1
     * 2. Send first 5 characters of hash to HIBP API
     * 3. HIBP returns all hashes starting with those 5 chars
     * 4. Check locally if full hash matches any returned hash
     * 
     * Privacy: HIBP never sees your actual password or full hash!
     */
    private boolean checkPasswordBreach(String password) {
       try {
            // hash password with SHA-1
            String sha1Hash = sha1Hash(password).toUpperCase();
            
            // Get first 5 characters (k-anonymity prefix)
            String prefix = sha1Hash.substring(0, 5);
            String suffix = sha1Hash.substring(5);

            // Query HIBP API with prefix
            String response = haveibeenpwnedClient
                .get()
                .uri("/range/" + prefix)
                .retrieve()
                .bodyToMono(String.class)
                .block();

            //check if our suffix appears in response
            if(response != null){
                return response.contains(suffix);
            }

            return false;

       } catch (Exception e) {
            // Log error but don't fail - breach check is optional
            System.err.println("Breach check failed: " + e.getMessage());
            return false;
       }

    }

    /**
     * Check all passwords for a user
     * 
     * @param userId User ID
     * @param masterPassword User's master password (to decrypt passwords)
     * @return List of breached password entries
     */
    private List<BreachedPasswordInfo> checkAllPasswords(Long userId, String masterPassword) {
        
        List<BreachedPasswordInfo> breachedPasswords = new ArrayList<>();

        //load user
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new IllegalArgumentException("User not found"));

        //derive encryption key from master password
        String encryptionKey = argon2Service.deriveEncryptionKey(masterPassword, user.getSalt());

        //Get all password entries
        List<PasswordEntry> entries = passwordEntryRepository.findByUserId(userId);

        for (PasswordEntry passwordEntry : entries) {
            try {
                //Decrypt password
                String decryptedPassword = encryptionService.decrypt(passwordEntry.getEncryptedPassword(), passwordEntry.getIv(), encryptionKey);

                //Chek breach
                boolean isBreached = checkPasswordBreach(decryptedPassword);

                //Update entry if breached
                passwordEntry.setBreached(isBreached);
                passwordEntry.setLastBreachCheck(LocalDateTime.now());
                passwordEntryRepository.save(passwordEntry);

                //Add to result if breached
                if(isBreached){
                    breachedPasswords.add(new BreachedPasswordInfo(
                        passwordEntry.getId(),
                        passwordEntry.getSiteName(),
                        passwordEntry.getUsername(),
                        passwordEntry.getLastBreachCheck(),
                        true,
                        null
                    ));
                }

            } catch (Exception e) {
                 System.err.println("Failed to check password entry " + passwordEntry.getId() + ": " + e.getMessage());
            }
        }

        return breachedPasswords; 
    }


    /**
     * Scheduled task to check all passwords periodically
     * Runs every day at 2 AM
     */
    @Scheduled(cron = "0 0 2 * * *")
    private void scheduleBreachCheck() {
        System.out.println("Starting scheduled breach check at " + LocalDateTime.now());
        
        // This would need to iterate through all users
        // For now, it's a placeholder
        // In production, you'd queue this job and process users in batches
        
        System.out.println("Scheduled breach check completed");
    }

    /**
     * SHA-1 hash for HIBP API
     * Note: SHA-1 is used because that's what HIBP expects, not for security
     */
    private String sha1Hash(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] hashBytes = digest.digest(password.getBytes(StandardCharsets.UTF_8));

            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) sb.append('0');
                sb.append(hex);
            }
            return sb.toString();
            
        } catch (Exception e) {
           throw new RuntimeException("SHA-1 hashing failed", e);
        }
    }
}