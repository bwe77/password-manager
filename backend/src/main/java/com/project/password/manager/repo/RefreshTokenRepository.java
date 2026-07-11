package com.project.password.manager.repo;

import com.project.password.manager.models.RefreshToken;
import org.springframework.data.repository.CrudRepository;

public interface RefreshTokenRepository extends CrudRepository<RefreshToken, String> {
    // Spring Data Redis gives us save / findById / existsById / deleteById for free,
    // keyed by the @Id field (the token string) on RefreshToken.
}
