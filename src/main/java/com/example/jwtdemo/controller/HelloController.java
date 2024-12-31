package com.example.jwtdemo.controller;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

@RestController
public class HelloController {

    @Autowired
    private UserDetailsService userDetailsService;


    @GetMapping("/hello")
    public String getHello() {
        return "Hello World!";
    }

    @PostMapping("/hello")
    public String postHello() {
        return "Hello, POST!";
    }

    @GetMapping("/admin")
    public String getAdmin() {
        return "Only admin users can view this";
    }

    @GetMapping("/user")
    public String getUser() {
        return "Only users can view this";
    }

    /*
     * Return user details for given username.
     * For user role, can access only their own user details
     * For admin role, can access all user details
     */

    // Authorization in method level (need to EnableMethodSecurity)
    // @PreAuthorize("hasRole('ADMIN') or #username == authentication.principal.username")
    @GetMapping("/user/{username}")
    public String getUserDetails(@PathVariable String username) {
        return userDetailsService.loadUserByUsername(username).toString();
    }

}
