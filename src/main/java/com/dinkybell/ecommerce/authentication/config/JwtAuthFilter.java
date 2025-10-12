package com.dinkybell.ecommerce.authentication.config;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.dinkybell.ecommerce.authentication.entity.UserAuthentication;
import com.dinkybell.ecommerce.authentication.repository.UserAuthenticationRepository;
import com.dinkybell.ecommerce.authentication.service.TokenBlacklistService;
import com.dinkybell.ecommerce.authentication.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

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
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserAuthenticationRepository userAuthRepository;
    private final TokenBlacklistService tokenBlacklistService;

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
            log.info("No Bearer token found in request headers");
            filterChain.doFilter(request, response);
            return;
        }
        
        // Extract token by removing "Bearer " prefix
        final String token = authHeader.substring(7);
        log.info("Token estratto dall'Header!");
        
        try {

            // Check if token is expired
            if (jwtUtil.isTokenExpired(token)) {
                log.info("Token scaduto o non valido - restituisco risposta 401 con header specifico");
                // Add a specific header to indicate token expiration
                response.setHeader("X-Token-Expired", "true");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("{\"error\":\"Token JWT scaduto. È necessario richiedere un nuovo token.\"}");
                return;
            }

            // Extract JWT ID to check if token is blacklisted
            String jti = jwtUtil.extractJti(token);
            log.info("JWT ID estratto: {}", jti);
            if (tokenBlacklistService.isBlacklisted(jti)) {
                // Token is blacklisted (user logged out), return 401 with specific header
                log.info("Token è in blacklist - restituisco risposta 401 con header specifico");
                response.setHeader("X-Token-Blacklisted", "true");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("{\"error\":\"Token JWT invalidato (logout). È necessario effettuare nuovamente il login.\"}");
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
        } catch (io.jsonwebtoken.security.SignatureException e) {
            // JWT signature is invalid (app restart with new keys)
            log.warn("JWT signature validation failed: {}", e.getMessage());
            response.setHeader("X-Token-Invalid", "true");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"error\":\"Token JWT non valido. È necessario effettuare nuovamente il login.\"}");
            return;
        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            // Token is expired
            log.info("JWT expired at {}, current time: {}", e.getClaims().getExpiration(), new Date());
            response.setHeader("X-Token-Expired", "true");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"error\":\"Token JWT scaduto. È necessario richiedere un nuovo token.\"}");
            return;
        } catch (Exception e) {
            // Log error and return appropriate response
            log.error("Error processing JWT token", e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"error\":\"Errore di autenticazione\"}");
            return;
        }
        
        // Continue filter chain
        filterChain.doFilter(request, response);
    }
}
