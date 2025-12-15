package com.project.password.manager.models;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "audit_logs", indexes = @Index(name = "idx_user_timestamp", columnList = "user_id, timestamp"))
public class AuditLog {
    @Id @GeneratedValue
    private Long id;
    
    @ManyToOne
    private User user;
    
    @Enumerated(EnumType.STRING)
    private AuditAction action; // LOGIN, PASSWORD_ACCESSED, PASSWORD_CREATED, etc.
    
    private Long passwordEntryId;
    private String ipAddress;
    private String userAgent;
    
    private LocalDateTime timestamp;
    private String details; // JSON string with additional context
    
    public Long getId() {
        return id;
    }
    public void setId(Long id) {
        this.id = id;
    }
    public User getUser() {
        return user;
    }
    public void setUser(User user) {
        this.user = user;
    }
    public AuditAction getAction() {
        return action;
    }
    public void setAction(AuditAction action) {
        this.action = action;
    }
    public Long getPasswordEntryId() {
        return passwordEntryId;
    }
    public void setPasswordEntryId(Long passwordEntryId) {
        this.passwordEntryId = passwordEntryId;
    }
    public String getIpAddress() {
        return ipAddress;
    }
    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }
    public String getUserAgent() {
        return userAgent;
    }
    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }
    public LocalDateTime getTimestamp() {
        return timestamp;
    }
    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }
    public String getDetails() {
        return details;
    }
    public void setDetails(String details) {
        this.details = details;
    }
}