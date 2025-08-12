package com.dinkybell.ecommerce.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.dinkybell.ecommerce.dtos.RegisterRequestDTO;
import com.dinkybell.ecommerce.services.UserAuthenticationService;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/auth")
public class UserAthenticationController {

    @Autowired
    private UserAuthenticationService userAuthenticationService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody @Valid RegisterRequestDTO request) {
        // Call the service to register the user
        return userAuthenticationService.registerUser(request.getEmail(), request.getPassword());
    }

    @GetMapping("/confirm-email")
    public ResponseEntity<?> confirmEmail(@RequestParam String token) {
        System.out.println("Confirming email with token: " + token);
        return userAuthenticationService.confirmEmail(token);
    }

}
