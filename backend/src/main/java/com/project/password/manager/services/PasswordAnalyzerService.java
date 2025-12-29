package com.project.password.manager.services;

import org.springframework.stereotype.Service;
import java.util.regex.Pattern;

/**
 * Password Analyzer Service
 * 
 * Analyzes password strength and provides recommendations.
 * This is a simplified implementation - can be enhanced later.
 */
@Service
public class PasswordAnalyzerService {
    // Calculate entropy, check patterns, common passwords
    // checkForReuse(Long userId, String password) -> boolean
    // analyzePasswordHealth(Long userId) -> PasswordHealthReport

    //common passwor dpatterns
    private static final Pattern HAS_UPPERCASE = Pattern.compile("[A-Z]");
    private static final Pattern HAS_LOWERCASE = Pattern.compile("[a-z]");
    private static final Pattern HAS_NUMBER = Pattern.compile("\\d");
    private static final Pattern HAS_SPECIAL = Pattern.compile("[!@#$%^&*(),.?\":{}|<>]");

    /**
     * Calculate password strength score (0-100)
     * 
     * Scoring:
     * - Length: up to 40 points
     * - Character variety: up to 40 points
     * - Unpredictability: up to 20 points
     * 
     * @param password Password to analyze
     * @return Strength score (0-100)
     */
    public int calculateStrength(String password){
        if(password == null || password.isEmpty()){
            return 0;
        }

        int score = 0;

        // Length score (up to 40 points)
        int length = password.length();
        if (length >= 8) score += 10;
        if (length >= 12) score += 10;
        if (length >= 16) score += 10;
        if (length >= 20) score += 10;

        // Character variety (up to 40 points)
        if (HAS_UPPERCASE.matcher(password).find()) score += 10;
        if (HAS_LOWERCASE.matcher(password).find()) score += 10;
        if (HAS_NUMBER.matcher(password).find()) score += 10;
        if (HAS_SPECIAL.matcher(password).find()) score += 10;

        // Unpredictability score (up to 20 points)
        // Check for common patterns
        if (!containsCommonPattern(password)) {
            score += 20;
        } else {
            score -= 10; // Penalty for common patterns
        }

        // Ensure score is between 0 and 100
        return Math.max(0, Math.min(100, score));
    }

    /**
     * Check if password contains common patterns
     * 
     * @param password Password to check
     * @return true if contains common patterns
     */
    public boolean containsCommonPattern(String password){
        String lowerPassword = password.toLowerCase();

        String[] commonPatterns = {"1234", "password", "qwerty", "abcd", "letmein", "welcome", "admin"};

        for (String pattern : commonPatterns) {
            if (lowerPassword.contains(pattern)) {
                return true;
            }
        }

        for(String common : commonPatterns) {
            if (lowerPassword.equals(common)) {
                return true;
            }
        }

        //check for sequential chars
        if(lowerPassword.contains("abcd") || lowerPassword.contains("1234") || lowerPassword.contains("qwerty")) {
            return true;
        }

        // Check for repeated characters
        if (password.matches(".*(.)\\1{2,}.*")) {
            return true;
        }

        return false;
    }

    public String getStrengthVerdict(Integer score){
        switch(score){
            case 0, 10, 20, 30:
                return "Very Weak";
            case 40, 50:
                return "Weak";
            case 60, 70:
                return "Moderate";
            case 80, 90:
                return "Strong";
            case 100:
                return "Very Strong";
            default:
                return "Unknown";
        }
    }
}