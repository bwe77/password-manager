package com.project.password.manager.services;

import com.project.password.manager.dto.request.GeneratePasswordRequest;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Service
public class PasswordGeneratorService {

    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String NUMBERS = "0123456789";
    private static final String SYMBOLS = "!@#$%^&*()-_=+[]{}";

    private final SecureRandom secureRandom = new SecureRandom();

    // generatePassword(GeneratePasswordRequest) -> String
    public String generatePassword(GeneratePasswordRequest req){
        int length = (req.length() >= 8) ? req.length() : 16;

        // includeUppercase/includeLowercase return primitive boolean, so no null check needed
        boolean upper = req.includeUppercase();
        boolean lower = req.includeLowercase();
        boolean numbers = req.includeNumbers();
        boolean symbols = req.includeSymbols();

        if(!(upper || lower || numbers || symbols)){
            throw new IllegalArgumentException("At least one character type must be selected");
        }

        StringBuilder pool = new StringBuilder();
        List<Character> passwordChars = new ArrayList<>();

        // Ensure at least one character from each selected type is included
        if(upper){ pool.append(UPPER); passwordChars.add(randomChar(UPPER)); }
        if(lower){ pool.append(LOWER); passwordChars.add(randomChar(LOWER)); }
        if(numbers){ pool.append(NUMBERS); passwordChars.add(randomChar(NUMBERS)); }
        if(symbols){ pool.append(SYMBOLS); passwordChars.add(randomChar(SYMBOLS)); }

        String all = pool.toString();
        while(passwordChars.size()< length){
            passwordChars.add(all.charAt(secureRandom.nextInt(all.length())));
        }

        // Shuffle to avoid predictable patterns
        Collections.shuffle(passwordChars, secureRandom);
        StringBuilder result = new StringBuilder();
        for(char c : passwordChars){
            result.append(c);
        }
        return result.toString();
    }

    private char randomChar(String chars) {
        int index = secureRandom.nextInt(chars.length());
        return chars.charAt(index);
    }
    
}