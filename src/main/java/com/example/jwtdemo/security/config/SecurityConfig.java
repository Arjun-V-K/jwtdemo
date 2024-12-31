package com.example.jwtdemo.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;


@Configuration
// @EnableMethodSecurity
public class SecurityConfig {

    /*
     * To enable username and password authentication, we need to provide two beans to spring context
     *  1. UserDetailsService - this is provided by marking SecurityUserService with @Component
     *  2. PasswordEncoder
     */

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.sessionManagement(c -> c.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        
        http.csrf(c -> c.disable());

        http.httpBasic(Customizer.withDefaults());

        http.authorizeHttpRequests(
            c -> c
            // .requestMatchers("/admin").hasRole("ADMIN")
            // .requestMatchers("/user").hasRole("USER")
            // .requestMatchers("/user/{username}").access(new WebExpressionAuthorizationManager("hasRole('ADMIN') or #username == authentication.principal.username"))
            // .anyRequest().authenticated()
            .requestMatchers(HttpMethod.POST, "/api/user").permitAll() /* Allow for user registration without authentication */
            .requestMatchers("/admin").hasRole("ADMIN")
            .anyRequest().authenticated()
        );  

        return http.build();
    }

}
