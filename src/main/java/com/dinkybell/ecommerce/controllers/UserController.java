package com.dinkybell.ecommerce.controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

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
public class UserController {

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
        System.out.println(username);
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
