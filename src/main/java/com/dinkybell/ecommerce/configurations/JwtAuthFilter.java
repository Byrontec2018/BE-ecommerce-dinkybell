package com.dinkybell.ecommerce.configurations;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.dinkybell.ecommerce.entities.UserAuthentication;
import com.dinkybell.ecommerce.repositories.UserAuthenticationRepository;
import com.dinkybell.ecommerce.services.TokenBlacklistService;
import com.dinkybell.ecommerce.utils.JwtUtil;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Filter for JWT authentication that intercepts requests and validates JWT tokens.
 * 
 * This filter checks for a valid JWT token in the Authorization header,
 * validates it, and sets up the security context if the token is valid.
 * It is executed once per request in the filter chain.
 */
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserAuthenticationRepository userAuthRepository;
    
    @Autowired
    private TokenBlacklistService tokenBlacklistService;

    /**
     * Processes each request to check for and validate JWT tokens.
     * 
     * If a valid token is found, it sets up the authentication in the SecurityContext.
     * 
     * @param request The HTTP request
     * @param response The HTTP response
     * @param filterChain The filter chain to continue processing the request
     * @throws ServletException if a servlet error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {
        
        // Get authorization header
        final String authHeader = request.getHeader("Authorization");
        
        // Check if Authorization header exists and starts with "Bearer "
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        
        // Extract token by removing "Bearer " prefix
        final String token = authHeader.substring(7);
        
        try {
            // Extract JWT ID to check if token is blacklisted
            String jti = jwtUtil.extractJti(token);
            if (tokenBlacklistService.isBlacklisted(jti)) {
                // Token is blacklisted (user logged out), continue chain without authentication
                filterChain.doFilter(request, response);
                return;
            }
           
            // Check if token is expired
            if (jwtUtil.isTokenExpired(token)) {
                filterChain.doFilter(request, response);
                return;
            }

            // Extract email from token
            final String email = jwtUtil.extractEmail(token);
            
            // If email exists and authentication is not already set
            if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                
                // Get user from database
                UserAuthentication userAuth = userAuthRepository.findByEmail(email).orElse(null);
                
                if (userAuth != null && jwtUtil.validateToken(token, email)) {
                    // Get claims to extract roles
                    Claims claims = jwtUtil.getAllClaimsFromToken(token);
                    String role = claims.get("roles", String.class);
                    
                    // Create authorities list from user roles
                    Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                    if (role != null) {
                        authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
                    }
                    
                    // Create user details
                    UserDetails userDetails = new User(userAuth.getEmail(), 
                            userAuth.getPassword(), userAuth.isEnabled(), true, true, true, authorities);
                    
                    // Create authentication token
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, authorities);
                    
                    // Set authentication details
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    
                    // Set authentication in security context
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (Exception e) {
            // Log error and continue without authentication
            logger.error("Error processing JWT token", e);
        }
        
        // Continue filter chain
        filterChain.doFilter(request, response);
    }
}
