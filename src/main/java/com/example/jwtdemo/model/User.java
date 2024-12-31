package com.example.jwtdemo.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * Represents the User schema stored in database.
 * 
 * Does not have fine grained authority control, just a single role.
 */
@Document(collection = "users")
@Data
@AllArgsConstructor
public class User {

    @Id
    private String id;
    private String username;
    private String password;
    private String role;

}
