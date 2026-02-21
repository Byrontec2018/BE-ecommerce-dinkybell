package com.dinkybell.ecommerce.user.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.dinkybell.ecommerce.authentication.entity.UserAuthentication;
import com.dinkybell.ecommerce.authentication.repository.UserAuthenticationRepository;
import lombok.RequiredArgsConstructor;

import java.util.HashMap;
import java.util.Map;

/**
 * REST Controller for user-related operations.
 * 
 * This controller handles operations related to authenticated users. All endpoints in this
 * controller require valid JWT authentication.
 * 
 * All endpoints are mapped under the "/users" base path.
 */
@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserAuthenticationRepository userAuthRepository;

    /**
     * Test endpoint for JWT authentication - accessible to any authenticated user.
     * This endpoint returns the current user's information extracted from JWT token.
     * 
     * @return ResponseEntity with user info or error message
     */
    @GetMapping("/profile")
    public ResponseEntity<Map<String, Object>> getUserProfile() {
        
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        Map<String, Object> response = new HashMap<>();
        
        if (auth == null || !auth.isAuthenticated()) {
            response.put("error", "User not authenticated");
            return ResponseEntity.status(401).body(response);
        }
        
        String email = auth.getName();
        UserAuthentication user = userAuthRepository.findByEmail(email).orElse(null);
        
        if (user != null) {
            response.put("id", user.getId());
            response.put("email", user.getEmail());
            response.put("role", user.getRole());
            response.put("active", user.isActive());
            response.put("message", "JWT Authentication successful!");
        } else {
            response.put("error", "User not found");
            return ResponseEntity.status(404).body(response);
        }
        
        return ResponseEntity.ok(response);
    }

    /**
     * Test endpoint accessible only to ADMIN users.
     * Tests role-based authentication with JWT.
     * 
     * @return ResponseEntity with admin-specific content
     */
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/test")
    public ResponseEntity<Map<String, Object>> getAdminTest() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Admin access granted!");
        response.put("user", auth.getName());
        response.put("authorities", auth.getAuthorities());
        response.put("timestamp", System.currentTimeMillis());
        
        return ResponseEntity.ok(response);
    }

    /**
     * Test endpoint accessible to any authenticated user (USER or ADMIN).
     * Tests basic JWT authentication.
     * 
     * @return ResponseEntity with user-specific content
     */
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    @GetMapping("/protected")
    public ResponseEntity<Map<String, Object>> getProtectedResource() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Access granted to protected resource!");
        response.put("user", auth.getName());
        response.put("role", auth.getAuthorities());
        response.put("authenticated", auth.isAuthenticated());
        
        return ResponseEntity.ok(response);
    }

    /**
     * Public endpoint that doesn't require authentication.
     * Can be used to test that JWT filter doesn't interfere with public endpoints.
     * 
     * @return Public message
     */
    @GetMapping("/public")
    public ResponseEntity<Map<String, Object>> getPublicResource() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This is a public endpoint - no authentication required");
        response.put("timestamp", System.currentTimeMillis());
        
        return ResponseEntity.ok(response);
    }

    /**
     * Example endpoint showing user greeting based on role.
     * 
     * This is a placeholder implementation that will be replaced with proper user management
     * functionality.
     * 
     * @param username The username to greet
     * @return A greeting message based on the username
     */
    @GetMapping("/login")
    public String getMethodName(@RequestParam String username) {
        // Logic to handle user login
        // This is a placeholder implementation
        log.info("Processing username: {}", username);
        if ("admin".equals(username)) {
            return "Welcome Admin!";
        } else if ("user".equals(username)) {
            return "Welcome User!";
        } else if (username == null || username.isEmpty()) {
            return "Please provide a valid username.";
        }
        return "Welcome Guest!";
    }

}
