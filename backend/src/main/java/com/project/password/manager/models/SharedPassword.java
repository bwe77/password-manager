package com.project.password.manager.models;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "shared_passwords")
public class SharedPassword {
    @Id @GeneratedValue
    private Long id;
    
    @ManyToOne
    private PasswordEntry passwordEntry;
    
    private String sharedWithEmail;
    private String encryptedPasswordForRecipient;
    
    private LocalDateTime sharedAt;
    private LocalDateTime expiresAt;
    private boolean revoked;
    
    private Integer accessCount;
    private Integer maxAccessCount;
    
    public Long getId() {
        return id;
    }
    public void setId(Long id) {
        this.id = id;
    }
    public PasswordEntry getPasswordEntry() {
        return passwordEntry;
    }
    public void setPasswordEntry(PasswordEntry passwordEntry) {
        this.passwordEntry = passwordEntry;
    }
    public String getSharedWithEmail() {
        return sharedWithEmail;
    }
    public void setSharedWithEmail(String sharedWithEmail) {
        this.sharedWithEmail = sharedWithEmail;
    }
    public String getEncryptedPasswordForRecipient() {
        return encryptedPasswordForRecipient;
    }
    public void setEncryptedPasswordForRecipient(String encryptedPasswordForRecipient) {
        this.encryptedPasswordForRecipient = encryptedPasswordForRecipient;
    }
    public LocalDateTime getSharedAt() {
        return sharedAt;
    }
    public void setSharedAt(LocalDateTime sharedAt) {
        this.sharedAt = sharedAt;
    }
    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }
    public void setExpiresAt(LocalDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }
    public boolean isRevoked() {
        return revoked;
    }
    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
    }
    public Integer getAccessCount() {
        return accessCount;
    }
    public void setAccessCount(Integer accessCount) {
        this.accessCount = accessCount;
    }
    public Integer getMaxAccessCount() {
        return maxAccessCount;
    }
    public void setMaxAccessCount(Integer maxAccessCount) {
        this.maxAccessCount = maxAccessCount;
    }
}
