package com.project.password.manager.repo;

import com.project.password.manager.models.SharedPassword;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface SharedPasswordRepository extends JpaRepository<SharedPassword, Long> {
    List<SharedPassword> findByPasswordEntryIdAndRevokedFalse(Long entryId);
}
