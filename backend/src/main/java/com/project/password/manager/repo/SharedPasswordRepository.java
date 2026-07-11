package com.project.password.manager.repo;

import com.project.password.manager.models.SharedPassword;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface SharedPasswordRepository extends JpaRepository<SharedPassword, Long> {
    List<SharedPassword> findByPasswordEntryIdAndRevokedFalse(Long entryId);
}
