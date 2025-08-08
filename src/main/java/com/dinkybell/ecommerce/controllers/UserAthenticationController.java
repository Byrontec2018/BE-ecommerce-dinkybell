package com.dinkybell.ecommerce.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
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
        System.out.println(request.getEmail());
        System.out.println(request.getPassword());
        return userAuthenticationService.registerUser(request.getEmail(), request.getPassword());
    }

    @Autowired
    private JavaMailSender mailSender; // or MailSender mailSender;

    @GetMapping("/test-email")
    public ResponseEntity<?> testEmail() {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom("support@dinkybell.com");
            message.setTo("stefano.dinca@fastwebnet.it");
            message.setSubject("Test");
            message.setText("Email configuration working!");
            mailSender.send(message);
            return ResponseEntity.ok("Email sent successfully");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Email failed: " + e.getMessage());
        }
    }

}
