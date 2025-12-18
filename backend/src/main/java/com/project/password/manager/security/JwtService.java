package com.project.password.manager.security;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.stereotype.Service;

import com.project.password.manager.config.JwtProperties;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    private final JwtProperties jwtProperties;

    public JwtService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    public String extractUsername(String token) {
        
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extract a specific claim from the token.
     * 
    */

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {

        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);    
    }

    private Claims extractAllClaims(String token) {
        
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Generate JWT access token for a user.
     * 
     * @param email User's email (username)
     * @return JWT token string
     */

    public String generateToken(String email){
        return generateToken(new HashMap<>(), email);
    }

    /**
     * Generate JWT token with additional claims.
     * 
     * @param extraClaims Additional claims to include
     * @param email User's email
     * @return JWT token string
     */

    public String generateToken(Map<String, Object> extraClaims, String email) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(email)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtProperties.getExpirationMs()))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Generate refresh token (longer expiration).
     * 
     * @param email User's email
     * @return Refresh token string
     */

    public String generateRefreshToken(String email){
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtProperties.getRefreshExpirationMs()))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean istokenValid(String token, String userEmail){
        final String username = extractUsername(token);
        return (username.equals(userEmail)) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token){
        return extractClaim(token, Claims::getExpiration);
    }
    
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtProperties.getSecret());
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
