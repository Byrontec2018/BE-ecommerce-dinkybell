package com.dinkybell.ecommerce.controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;


@RestController
@RequestMapping("/users")
public class UserController {

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
