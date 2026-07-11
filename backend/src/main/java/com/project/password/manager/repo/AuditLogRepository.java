package com.project.password.manager.repo;

import com.project.password.manager.models.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.domain.Pageable;
import java.time.LocalDateTime;
import java.util.List;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    List<AuditLog> findByUserIdOrderByTimestampDesc(Long userId, Pageable pageable);
    
    @Query("SELECT a FROM AuditLog a WHERE a.user.id = :userId AND a.timestamp > :since")
    List<AuditLog> findRecentActivity(Long userId, LocalDateTime since);
}
