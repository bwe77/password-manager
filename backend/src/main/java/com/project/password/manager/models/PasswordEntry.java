package com.project.password.manager.models;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.Set;

@Entity
@Table(name = "password_entries")
public class PasswordEntry {
    @Id @GeneratedValue
    private Long id;
    
    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;
    
    private String siteName;
    private String siteUrl;
    private String username;
    
    @Column(length = 1000)
    private String encryptedPassword; // AES-256 encrypted
    
    private String iv; // Initialization vector
    private String notes; // encrypted
    
    
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private LocalDateTime lastAccessedAt;
    private LocalDateTime expiresAt;
    
    private boolean isBreached;
    private LocalDateTime lastBreachCheck;
    
    private Integer passwordStrength; // 0-100
    private boolean isFavorite;
    
    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    public LocalDateTime getLastAccessedAt() {
        return lastAccessedAt;
    }

    public void setLastAccessedAt(LocalDateTime lastAccessedAt) {
        this.lastAccessedAt = lastAccessedAt;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(LocalDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public boolean isBreached() {
        return isBreached;
    }

    public void setBreached(boolean isBreached) {
        this.isBreached = isBreached;
    }

    public LocalDateTime getLastBreachCheck() {
        return lastBreachCheck;
    }

    public void setLastBreachCheck(LocalDateTime lastBreachCheck) {
        this.lastBreachCheck = lastBreachCheck;
    }

    public Integer getPasswordStrength() {
        return passwordStrength;
    }

    public void setPasswordStrength(Integer passwordStrength) {
        this.passwordStrength = passwordStrength;
    }

    public boolean isFavorite() {
        return isFavorite;
    }

    public void setFavorite(boolean isFavorite) {
        this.isFavorite = isFavorite;
    }

    @ElementCollection
    private Set<String> tags;

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getSiteName() {
        return siteName;
    }

    public void setSiteName(String siteName) {
        this.siteName = siteName;
    }

    public String getSiteUrl() {
        return siteUrl;
    }

    public void setSiteUrl(String siteUrl) {
        this.siteUrl = siteUrl;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEncryptedPassword() {
        return encryptedPassword;
    }

    public void setEncryptedPassword(String encryptedPassword) {
        this.encryptedPassword = encryptedPassword;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }

}