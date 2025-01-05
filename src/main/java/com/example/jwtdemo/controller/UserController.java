package com.example.jwtdemo.controller;

import org.springframework.web.bind.annotation.RestController;

import com.example.jwtdemo.model.User;
import com.example.jwtdemo.repository.UserRepository;

import java.util.List;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;



@RestController
@RequestMapping("/api/user")
public class UserController {
    
    private UserRepository userRepository;

    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @PostMapping
    public User createUser() {
        User user = new User(null, "user", "password", "USER");
        return userRepository.save(user);
    }

    @DeleteMapping
    public void deleteAllUsers() {
        userRepository.deleteAll();
    }

}
