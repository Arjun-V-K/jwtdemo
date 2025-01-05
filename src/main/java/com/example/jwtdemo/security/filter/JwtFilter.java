package com.example.jwtdemo.security.filter;

import java.io.IOException;
import java.util.List;
import java.util.logging.Logger;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.jwtdemo.security.service.JwtService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtFilter extends OncePerRequestFilter {

    private final Logger logger = Logger.getLogger(JwtFilter.class.getName());

    private final JwtService jwtService;

    public JwtFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    } 

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String token = extractToken(request);

        if(token == null) {
            logger.info("No Bearer token found in Authorization Header");
            filterChain.doFilter(request, response);
            return;
        }

        logger.info(String.format("Found Bearer token '%s' in Authorization Header", token));

        if(!jwtService.verifyToken(token)) {
            // If JWT Token is present, but invalid
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            return; 
        }

        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        SecurityContextHolder.setContext(securityContext);
        securityContext.setAuthentication(new UsernamePasswordAuthenticationToken(jwtService.extractUsername(token), null, List.of(() -> "USER")));

        logger.info(String.format("Set SecurityContext to %s", SecurityContextHolder.getContext().toString()));

        /* Forward the request to the next filter in the filter chain */
        filterChain.doFilter(request, response);

    }

    /**
     * Extract the Bearer token in Authorization header from HttpRequest
     * 
     * In Spring, it is provided by the AuthenticationConvertor interface
     */
    private String extractToken(HttpServletRequest request) {
        
        String AUTHENTICATION_SCHEME_BASIC = "Bearer";

        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null) {
            return null;
        }
		header = header.trim();
        if (!StringUtils.startsWithIgnoreCase(header, AUTHENTICATION_SCHEME_BASIC)) {
			return null;
		}
        return header.substring(6).trim();
    }

}
