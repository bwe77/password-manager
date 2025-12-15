package com.project.password.manager.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.project.password.manager.models.PasswordEntry;
import org.springframework.data.jpa.repository.Query;
import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface PasswordEntryRepository extends JpaRepository<PasswordEntry, Long> {
    List<PasswordEntry> findByUserId(Long userId);
    
    @Query("SELECT p FROM PasswordEntry p WHERE p.user.id = :userId AND p.isBreached = true")
    List<PasswordEntry> findBreachedPasswords(Long userId);
    
    @Query("SELECT p FROM PasswordEntry p WHERE p.user.id = :userId AND p.passwordStrength < :threshold")
    List<PasswordEntry> findWeakPasswords(Long userId, Integer threshold);
    
    @Query("SELECT p FROM PasswordEntry p WHERE p.user.id = :userId AND p.expiresAt < :date")
    List<PasswordEntry> findExpiredPasswords(Long userId, LocalDateTime date);
}
