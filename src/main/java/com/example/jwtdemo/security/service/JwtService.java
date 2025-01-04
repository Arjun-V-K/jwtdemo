package com.example.jwtdemo.security.service;

import java.util.Date;
import java.util.logging.Logger;

import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

@Service
public class JwtService {

    private Logger logger = Logger.getLogger(JwtService.class.getName());

    private final String SECRET_KEY = "secret";
    private final String ISSUER = "scholarly";
    private final long MINUTES_TO_EXPIRY = 5;

    private final Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);

    private final JWTVerifier jwtVerifier = JWT.require(algorithm).withIssuer(ISSUER).build();

    public String createToken(String username) {
        return JWT.create()
            .withIssuer(ISSUER)
            .withSubject(username)
            .withClaim("rol", "USER") // TODO: Role is hardcoded now
            .withIssuedAt(new Date())
            .withExpiresAt(new Date(System.currentTimeMillis() + MINUTES_TO_EXPIRY * 60 * 1000))
            .sign(algorithm);
    }

    public boolean verifyToken(String jwtToken) {

        DecodedJWT decodedJWT;
        try {
            decodedJWT = jwtVerifier.verify(jwtToken);
        }
        catch(JWTVerificationException e) {
            e.printStackTrace();
            logger.info(String.format("Given JWT token '%s' is invalid. Exception: %s", jwtToken, e.getMessage()));
            return false;
        }

        logger.info(String.format("Given JWT token '%s' is valid. Found username '%s' with role '%s'", jwtToken, decodedJWT.getSubject(), decodedJWT.getClaim("rol").toString()));

        return true;
    }

    public String extractUsername(String jwtToken) {
        return jwtVerifier.verify(jwtToken).getSubject();
    }

    public String extractRole(String jwtToken) {
        return jwtVerifier.verify(jwtToken).getClaim("rol").toString();
    }

}
