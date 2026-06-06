package com.cordillera.api_ateway.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;

@Component
public class JwtUtil {

    private final Key signingKey;

    public JwtUtil(@Value("${jwt.secret:cordillera-secret-key-which-should-be-very-long}") String secret) {
        byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
        this.signingKey = Keys.hmacShaKeyFor(secretBytes.length >= 32 ? secretBytes : padSecret(secretBytes));
    }

    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }

    public boolean validateToken(String token) {
        try {
            extractClaims(token);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    private Claims extractClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private byte[] padSecret(byte[] secretBytes) {
        byte[] padded = new byte[32];
        System.arraycopy(secretBytes, 0, padded, 0, Math.min(secretBytes.length, padded.length));
        return padded;
    }
}
