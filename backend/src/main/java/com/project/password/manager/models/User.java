package com.project.password.manager.models;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;
@Entity
@Table(name = "users")
public class User {
    @Id @GeneratedValue
    private Long id;
    
    private String email;
    private String masterPasswordHash; // Argon2 hash
    private String salt;

    private String totpSecret; // encrypted
    private boolean totpEnabled;
    
    private LocalDateTime createdAt;
    private LocalDateTime lastLoginAt;
    
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    private List<PasswordEntry> passwordEntries;
    
    @OneToMany(mappedBy = "user")
    private List<AuditLog> auditLogs;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getMasterPasswordHash() {
        return masterPasswordHash;
    }

    public void setMasterPasswordHash(String masterPasswordHash) {
        this.masterPasswordHash = masterPasswordHash;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }
}
