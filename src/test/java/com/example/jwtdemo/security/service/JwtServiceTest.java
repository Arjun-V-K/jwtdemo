package com.example.jwtdemo.security.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.keygen.KeyGenerators;


public class JwtServiceTest {

    private JwtService jwtService;

    @BeforeEach
    public void setUp() {
        jwtService = new JwtService();
    }

    @Test
    public void testCreateToken() {
        String token = jwtService.createToken("testuser");
        assertNotNull(token);
    }

    @Test
    public void testVerifyToken_ValidToken() {
        String token = jwtService.createToken("testuser");
        boolean isValid = jwtService.verifyToken(token);
        assertTrue(isValid);
    }

    @Test
    public void testVerifyToken_InvalidToken() {
        String invalidToken = "invalid.token.here";
        boolean isValid = jwtService.verifyToken(invalidToken);
        assertFalse(isValid);
    }

    @Test
    public void testVerifyToken_ExpiredToken() throws InterruptedException {
        String token = jwtService.createToken("testuser");
        // Wait for the token to expire (assuming expiration time is 1 second for testing)
        Thread.sleep(2000);
        boolean isValid = jwtService.verifyToken(token);
        assertFalse(isValid);
    }

    @Test
    public void testGenerateToken() throws NoSuchAlgorithmException {
        String KEY = KeyGenerators.string().generateKey();
        System.out.println("Generated Key: " + KEY);

        // Generate a secure random key
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
        keyGen.init(256); // Specify key size
        SecretKey secretKey = keyGen.generateKey();

        // Encode the key as a Base64 string (for use as a shared secret)
        String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());

        System.out.println("Generated Key: " + encodedKey);

    }
}
