# JWT Demo Application

This is a simple Spring Boot demo application that implements JWT (JSON Web Token) authentication using the Auth0 Java JWT library. The project demonstrates how to secure REST APIs with JWT in a Spring environment.

## Features

- User model persisted in MongoDB.
- REST endpoints for basic user operations.
- JWT token creation and validation using Auth0's `java-jwt` library.
- Custom `JwtFilter` for protecting endpoints.
- Role-based security (role is currently hardcoded for demonstration).
- Example of extracting user information from JWT.
- Sample unit tests for JWT service.

## Tech Stack

- Java
- Spring Boot
- Spring Security
- MongoDB (with Spring Data MongoDB)
- Auth0 Java JWT (`com.auth0.jwt`)
- JUnit for testing

## Usage Overview

- The application generates JWTs with a short expiry for demonstration.
- Use the token in the `Authorization: Bearer <token>` header for protected endpoints.
- The JWT is signed using HMAC256 and a sample secret (see `JwtService.java`).
- The issuer is set to `scholarly`.  
- The role is hardcoded to `"USER"` for now.

## Notes

- This project is for demonstration purposes and is not production ready.
- Do not use the hardcoded secret in production; always secure and manage secrets properly.
- Role and user management are minimal for simplicity.

## License

This project is open source and available under the [MIT License](LICENSE).
