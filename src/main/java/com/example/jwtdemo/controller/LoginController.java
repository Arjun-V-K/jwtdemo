package com.example.jwtdemo.controller;

import org.springframework.web.bind.annotation.RestController;

import com.example.jwtdemo.security.service.JwtService;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
public class LoginController {

    private final JwtService jwtService;

    public LoginController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @GetMapping("/login")
    public ResponseEntity<Void> login(HttpServletResponse response, Authentication authentication) {
        // Add it to the Header or Cookie
        response.addHeader("JWT-Token", jwtService.createToken(authentication.getName()));
        return ResponseEntity.ok().build();
    }

}
