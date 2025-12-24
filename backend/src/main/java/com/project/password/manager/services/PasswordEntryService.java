package com.project.password.manager.services;

import com.project.password.manager.dto.request.CreatePasswordRequest;
import com.project.password.manager.dto.request.UpdatePasswordRequest;
import com.project.password.manager.dto.response.PasswordDetailResponse;
import com.project.password.manager.dto.response.PasswordEntryResponse;
import com.project.password.manager.models.PasswordEntry;
import com.project.password.manager.models.User;
import com.project.password.manager.repo.PasswordEntryRepository;
import com.project.password.manager.repo.UserRepository;
import com.project.password.manager.security.Argon2Service;
import com.project.password.manager.security.EncryptionService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;
/**
 * Password Entry Service
 * 
 * Handles CRUD operations for password vault entries.
 * Integrates encryption for zero-knowledge architecture.
 */
@Service
public class PasswordEntryService {
    
    private final PasswordEntryRepository passwordEntryRepository;
    private final UserRepository userRepository;
    private final EncryptionService encryptionService;
    private final Argon2Service argon2Service;
    private final PasswordAnalyzerService passwordAnalyzerService;

    public PasswordEntryService(PasswordEntryRepository passwordEntryRepository,
                                UserRepository userRepository,
                                EncryptionService encryptionService,
                                Argon2Service argon2Service, PasswordAnalyzerService passwordAnalyzerService) {
        this.passwordEntryRepository = passwordEntryRepository;
        this.userRepository = userRepository;
        this.encryptionService = encryptionService;
        this.argon2Service = argon2Service;
        this.passwordAnalyzerService = passwordAnalyzerService;
    }

    /**
     * Create a new password entry
     * 
     * Process:
     * 1. Load user from database
     * 2. Derive encryption key from master password
     * 3. Encrypt password with AES-256-GCM
     * 4. Analyze password strength
     * 5. Save encrypted data to database
     * 
     * @param userId User ID
     * @param masterPassword User's master password (for key derivation)
     * @param request Password creation request
     * @return Password entry response (without plaintext password)
     */
    @Transactional
    public PasswordEntryService createPassword(Long userId, String masterPassword, CreatePasswordRequest request){
        //load User
        User user = userRepository.findById(userId)
                .orElseThrow(()-> new RuntimeException("User not found"));
        
        //Derive encryption key
        String encryptionKey = argon2Service.deriveEncryptionKey(masterPassword, user.getSalt());

        // ecnrypt password
        EncryptionService.EncryptedData encryptedPassword = encryptionService.encrypt(request.password(), encryptionKey);

        //create PasswordEntry entity
        PasswordEntry entry = new PasswordEntry();
        entry.setUser(user);
        entry.setSiteName(request.siteName());
        entry.setSiteUrl(request.siteUrl());
        entry.setUsername(request.username());
        entry.setEncryptedPassword(encryptedPassword.getCiphertext());
        entry.setIv(encryptedPassword.getIv());

        //Encrypt notes if present
        if(request.notes() != null && !request.notes().isEmpty()){
            EncryptionService.EncryptedData encryptedNotes = encryptionService.encrypt(request.notes(), encryptionKey);
            entry.setNotes(encryptedNotes.getIv());
        }

        //Analyze password strength
        int strength = passwordAnalyzerService.analyzeStrength(request.password());
        entry.setPasswordStrength(strength);
        
        // Set timestamps
        entry.setCreatedAt(LocalDateTime.now());
        entry.setUpdatedAt(LocalDateTime.now());
        entry.setExpiresAt(request.expiresAt());
        
        // Set breach status (will be checked later)
        entry.setBreached(false);
        entry.setLastBreachCheck(LocalDateTime.now());

        // Save to database
        entry = passwordEntryRepository.save(entry);

        // Return response (without plaintext password)
        return toPasswordEntryResponse(entry);
    }

    /**
     * Get all password entries for a user (without decrypted passwords)
     * 
     * @param userId User ID
     * @return List of password entries
     */
    public List<PasswordEntryResponse> getAllPasswords(Long userId){
        List<PasswordEntry> entries = passwordEntryRepository.findByUserId(userId);
        return entries.stream()
                .map(this::toPasswordEntryResponse)
                .collect(Collectors.toList());
    }

    /**
     * Get a specific password entry with DECRYPTED password
     * 
     * This is the only endpoint that returns the actual password.
     * 
     * @param userId User ID
     * @param entryId Password entry ID
     * @param masterPassword User's master password (for decryption)
     * @return Password entry with decrypted password
     */
    @Transactional
    public PasswordDetailResponse getPasswordDetail(Long userId, Long entryId, String masterPassword){
        //load password entry
        PasswordEntry entry = passwordEntryRepository.findById(entryId)
                .orElseThrow(()-> new IllegalArgumentException("Password entry not found"));
        
        //verify ownership
        if(!entry.getUser().getId().equals(userId)){
            throw new SecurityException("Unauthorized access");
        }

        //load user 
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new IllegalArgumentException("User not found"));

        // Derive encryption key
        String encryptionKey = argon2Service.deriveEncryptionKey(masterPassword, user.getSalt());

        // Decrypt password
        String decryptedPassword = encryptionService.decrypt(
            entry.getEncryptedPassword(),
            entry.getIv(),
            encryptionKey
        );

        //Decrypt notes if present
        String decryptedNotes = null;
        if(entry.getNotes() != null && !entry.getNotes().isEmpty()){
            decryptedNotes = encryptionService.decrypt(
                entry.getNotes(),
                entry.getIv(),
                encryptionKey
            );
        }

        //update last accessed timestamp
        entry.setLastAccessedAt(LocalDateTime.now());
        passwordEntryRepository.save(entry);

        //return detailed response
        return new PasswordDetailResponse(
            entry.getId(),
            entry.getSiteName(),
            entry.getSiteUrl(),
            entry.getUsername(),
            decryptedPassword,  // ← Actual password included here
            decryptedNotes,
            entry.getCreatedAt(),
            entry.getUpdatedAt(),
            entry.getLastAccessedAt(),
            entry.getExpiresAt(),
            entry.isBreached(),
            entry.getPasswordStrength(),
            entry.isFavorite()
        );
    }

    /**
     * Update a password entry
     * 
     * @param userId User ID
     * @param entryId Password entry ID
     * @param masterPassword User's master password (for re-encryption)
     * @param request Update request
     * @return Updated password entry
     */
    @Transactional
    public PasswordEntryResponse updatePassword(Long userId, Long entryId, String masterPassword, UpdatePasswordRequest request) {
        //load password entry
        PasswordEntry entry = passwordEntryRepository.findById(entryId)
                .orElseThrow(()-> new IllegalArgumentException("Password entry not found"));
        
        //verify ownership
        if(!entry.getUser().getId().equals(userId)){
            throw new SecurityException("Unauthorized access");
        }
        
    }
    // Inner class for PasswordDetailResponse (create this in dto/response package)
    public record PasswordDetailResponse(
        Long id,
        String siteName,
        String siteUrl,
        String username,
        String password,  // ← Decrypted password included
        String notes,
        LocalDateTime createdAt,
        LocalDateTime updatedAt,
        LocalDateTime lastAccessedAt,
        LocalDateTime expiresAt,
        boolean isBreached,
        Integer passwordStrength,
        boolean isFavorite
    ) {}
}