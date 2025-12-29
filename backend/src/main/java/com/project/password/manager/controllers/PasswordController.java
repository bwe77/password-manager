package com.project.password.manager.controllers;


import com.project.password.manager.dto.request.CreatePasswordRequest;
import com.project.password.manager.dto.request.UpdatePasswordRequest;
import com.project.password.manager.dto.response.PasswordEntryResponse;
import com.project.password.manager.services.PasswordEntryService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Password Controller
 * 
 * Handles CRUD operations for password vault entries.
 * All endpoints require authentication.
 */
@RestController
@RequestMapping("/api/passwords")
@PreAuthorize("isAuthenticated()")
public class PasswordController {
    // GET / - list all passwords
    // GET /{id} - get specific password (decrypted)
    // POST / - create new password
    // PUT /{id} - update password
    // DELETE /{id} - delete password
    // GET /search?q=
    // POST /generate - generate password
    // POST /{id}/check-breach - manual breach check
    private final PasswordEntryService passwordEntryService;

    public PasswordController(PasswordEntryService passwordEntryService) {
        this.passwordEntryService = passwordEntryService;
    }

    /**
     * Create a new password entry
     * 
     * POST /api/passwords
     * 
     * Headers:
     * - Authorization: Bearer <access_token>
     * - X-Master-Password: <master_password>  (for encryption)
     * 
     * Body:
     * {
     *   "siteName": "Gmail",
     *   "siteUrl": "https://gmail.com",
     *   "username": "john@example.com",
     *   "password": "MySecurePassword123!",
     *   "notes": "Personal email account"
     * }
     * 
     * Response: 201 CREATED
     */
    @PostMapping
    public ResponseEntity<PasswordEntryResponse> createPassword(Authentication authentication,
            @RequestHeader("X-Master-Password") String masterPassword,
            @Valid @RequestBody CreatePasswordRequest request){

        Long userId = getUserIdFromAuth(authentication);
        PasswordEntryResponse response = passwordEntryService.createPassword(userId, masterPassword, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Get all password entries (without decrypted passwords)
     * 
     * GET /api/passwords
     * 
     * Response: 200 OK
     * [
     *   {
     *     "id": 1,
     *     "siteName": "Gmail",
     *     "username": "john@example.com",
     *     "createdAt": "2025-12-19T15:30:00",
     *     "passwordStrength": 85,
     *     "isBreached": false
     *   }
     * ]
     */
    @GetMapping
    public ResponseEntity<List<PasswordEntryResponse>> getAllPasswords(Authentication authentication) {
        Long userId = getUserIdFromAuth(authentication);
        List<PasswordEntryResponse> response = passwordEntryService.getAllPasswords(userId);
        return ResponseEntity.ok(response);
    }

    /**
     * Get specific password entry WITH decrypted password
     * 
     * GET /api/passwords/{id}
     * 
     * Headers:
     * - Authorization: Bearer <access_token>
     * - X-Master-Password: <master_password>  (for decryption)
     * 
     * Response: 200 OK
     * {
     *   "id": 1,
     *   "siteName": "Gmail",
     *   "username": "john@example.com",
     *   "password": "MySecurePassword123!",  ← Decrypted password
     *   "notes": "Personal email",
     *   "passwordStrength": 85
     * }
     */
    @GetMapping("/{id}")
    public ResponseEntity<?> getPasswordDetail(Authentication authentication, @PathVariable Long id,
            @RequestHeader("X-Master-Password") String masterPassword) {

        Long userId = getUserIdFromAuth(authentication);
        var detail = passwordEntryService.getPasswordDetail(userId, id, masterPassword);
        return ResponseEntity.ok(detail);
    }

    /**
     * Update password entry
     * 
     * PUT /api/passwords/{id}
     * 
     * Headers:
     * - Authorization: Bearer <access_token>
     * - X-Master-Password: <master_password>  (for re-encryption)
     */
    @PutMapping("/{id}")
    public ResponseEntity<PasswordEntryResponse> updatePassword(
            Authentication authentication,
            @PathVariable Long id,
            @RequestHeader("X-Master-Password") String masterPassword,
            @Valid @RequestBody UpdatePasswordRequest request
    ) {
        Long userId = getUserIdFromAuth(authentication);
        
        PasswordEntryResponse response = passwordEntryService.updatePassword(
            userId,
            id,
            masterPassword,
            request
        );
        
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deletePassword(Authentication authentication, @PathVariable Long id) {
        Long userId = getUserIdFromAuth(authentication);
        passwordEntryService.deletePassword(userId, id);
        return ResponseEntity.noContent().build();
    }

    /**
     * Search password entries
     * 
     * GET /api/passwords/search?q=gmail
     * 
     * Response: 200 OK
     */
    @GetMapping("/search")
    public ResponseEntity<List<PasswordEntryResponse>> searchPasswords(
            Authentication authentication,
            @RequestParam String q
    ) {
        Long userId = getUserIdFromAuth(authentication);
        List<PasswordEntryResponse> results = passwordEntryService.searchPasswords(userId, q);
        return ResponseEntity.ok(results);
    }

    /**
     * Generate a strong password
     * 
     * POST /api/passwords/generate
     * 
     * Body:
     * {
     *   "length": 20,
     *   "includeUppercase": true,
     *   "includeLowercase": true,
     *   "includeNumbers": true,
     *   "includeSymbols": true
     * }
     * 
     * TODO: Implement when PasswordGeneratorService is ready
     */
    @PostMapping("/generate")
    public ResponseEntity<?> generatePassword() {
        return ResponseEntity.ok()
            .body("{\"message\": \"Password generation - implement later\"}");
    }

    /**
     * Extract user ID from Authentication object
     * 
     * The JWT filter sets the authenticated user's email in the authentication.
     * We need to extract the user ID for database queries.
     * 
     * TODO: Consider storing user ID directly in JWT claims for efficiency
     */
    private Long getUserIdFromAuth(Authentication authentication) {
        // For now, return a placeholder
        // In production, you'd extract this from the JWT claims or load from database
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String email = userDetails.getUsername();
        
        // TODO: Load user ID from database or JWT claims
        // This is a simplified approach - optimize later
        return 1L; // Placeholder - implement proper user ID extraction
    }
}