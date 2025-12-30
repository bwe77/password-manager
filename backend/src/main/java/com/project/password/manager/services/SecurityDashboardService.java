package com.project.password.manager.services;

import com.project.password.manager.dto.response.SecurityDashboardResponse;
import com.project.password.manager.models.PasswordEntry;
import com.project.password.manager.repo.PasswordEntryRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

@Service
public class SecurityDashboardService {
    
    private final PasswordEntryRepository passwordEntryRepository;

    public SecurityDashboardService(PasswordEntryRepository passwordEntryRepository) {
        this.passwordEntryRepository = passwordEntryRepository;
    }

    /**
     * Get security dashboard overview for a user
     */
    public SecurityDashboardResponse getDashboard(Long userId){
        //Get all passwords
        List<PasswordEntry> passwords = passwordEntryRepository.findByUserId(userId);
        int total = passwords.size();

        //Count weak passwords (strength < 60)
        long weak = passwords.stream()
                .filter(p -> p.getPasswordStrength() != null && p.getPasswordStrength() < 60)
                .count();

        //Count breached passwords
        long breached = passwords.stream()
                .filter(p -> p.isBreached())
                .count();
        
        //Count reused passwords
        Map<String, Integer> passwordCountMap = new HashMap<>();
        for (PasswordEntry passwordEntry : passwords) {
            String encPwd = passwordEntry.getEncryptedPassword();
            passwordCountMap.put(encPwd, passwordCountMap.getOrDefault(encPwd, 0) + 1);
        }

        long reused = passwordCountMap.values().stream()
                .filter(count -> count > 1)
                .count();
        
        //Count expired passwords (older than 90 days)
        long expired = passwords.stream()
            .filter(p -> p.getExpiresAt() != null && p.getExpiresAt().isBefore(LocalDateTime.now()))
            .count();
        
        // Calculate overall security score (0-100)
        int score = calculateSecurityScore(total, (int)weak, (int)breached, (int)reused, (int)expired);

        // Generate recommendations
        List<String> recommendations = generateRecommendations((int)weak, (int)breached, (int)reused, (int)expired);

        return new SecurityDashboardResponse(
            total,
            (int)weak, 
            (int)breached, 
            (int)reused, 
            (int)expired, 
            score, 
            LocalDateTime.now(), 
            recommendations
        );
    }

    private List<String> generateRecommendations(int weak, int breached, int reused, int expired) {
        List<String> recommendations = new ArrayList<>();

        if (breached > 0) {
            recommendations.add("🚨 Change " + breached + " breached password" + (breached > 1 ? "s" : "") + " immediately!");
        }
        if (weak > 0) {
            recommendations.add("⚠️ Strengthen " + weak + " weak password" + (weak > 1 ? "s" : ""));
        }
        if (reused > 0) {
            recommendations.add("⚠️ Use unique passwords for each site (found " + reused + " reused)");
        }
        if (expired > 0) {
            recommendations.add("⏰ Update " + expired + " expired password" + (expired > 1 ? "s" : ""));
        }
        if (recommendations.isEmpty()) {
            recommendations.add("✅ Great job! Your passwords are secure!");
        }

        return recommendations;
    }

    private int calculateSecurityScore(int total, int weak, int breached, int reused, int expired) {
        if (total == 0) return 100;

        int score = 100;

        //Penalties
        score -= (weak * 100 / total) * 0.3;      // 30% weight for weak passwords
        score -= (breached * 100 / total) * 0.4;  // 40% weight for breached (critical!)
        score -= (reused * 100 / total) * 0.2;    // 20% weight for reused
        score -= (expired * 100 / total) * 0.1;   // 10% weight for expired

        return Math.max(0, Math.min(100, score));
    }
}
