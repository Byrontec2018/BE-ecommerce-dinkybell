package com.dinkybell.ecommerce.user.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import lombok.RequiredArgsConstructor;

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

    /**
     * Test endpoint for JWT authentication - accessible to any authenticated user.
     * This endpoint returns the current user's information extracted from JWT token.
     * 
     * @return ResponseEntity with user info or error message
     */
    @GetMapping("/profile")
    public ResponseEntity<?> getUserProfile() {
        return ResponseEntity.ok("Authenticated access to user profile");
    }

    /**
     * Test endpoint accessible only to ADMIN users.
     * Tests role-based authentication with JWT.
     * 
     * @return ResponseEntity with admin-specific content
     */
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/test")
    public ResponseEntity<?> getAdminTest() {       
        return ResponseEntity.ok("Authenticated access to admin resource");
    }

    /**
     * Test endpoint accessible to any authenticated user (USER or ADMIN).
     * Tests basic JWT authentication.
     * 
     * @return ResponseEntity with user-specific content
     */
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    @GetMapping("/protected")
    public ResponseEntity<?> getProtectedResource() {        
        return ResponseEntity.ok("Authenticated access to protected resource");
    }

    /**
     * Public endpoint that doesn't require authentication.
     * Can be used to test that JWT filter doesn't interfere with public endpoints.
     * 
     * @return Public message
     */
    @GetMapping("/public")
    public ResponseEntity<?> getPublicResource() {
        return ResponseEntity.ok("This is a public endpoint - no authentication required");
    }    

}
