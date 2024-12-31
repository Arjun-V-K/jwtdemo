package com.example.jwtdemo.security.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.example.jwtdemo.repository.UserRepository;
import com.example.jwtdemo.security.model.SecurityUser;

/**
 * Custom implementation of UserDetailsService.
 * 
 * Loads SecurityUser object from Database
 */
@Component
public class SecurityUserService implements UserDetailsService {

    private UserRepository userRepository;

    public SecurityUserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return new SecurityUser(userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Username not found")));
    }

}
