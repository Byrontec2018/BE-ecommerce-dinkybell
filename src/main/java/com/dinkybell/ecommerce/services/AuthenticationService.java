package com.dinkybell.ecommerce.services;

import java.time.LocalDateTime;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.task.TaskExecutionProperties.Simple;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.dinkybell.ecommerce.entities.Authentication;
import com.dinkybell.ecommerce.repositories.AuthenticationRepository;

public class AuthenticationService {

    @Autowired
    AuthenticationRepository authenticationRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    public ResponseEntity<?> registerUser(String email, String password) {

        // Check if email already exists
        if (authenticationRepository.existsByEmail(email)) {
            return ResponseEntity.badRequest().body("Email already exists");
        }

        // Create hashed password
        String hashedPassword = passwordEncoder.encode(password);

        // Generate reset token
        String resetToken = UUID.randomUUID().toString();

        Authentication userAuthentication = new Authentication();
        userAuthentication.setEmail(email);
        userAuthentication.setPassword(hashedPassword);
        userAuthentication.setResetToken(resetToken);
        userAuthentication.setResetTokenExpiry(LocalDateTime.now().plusMinutes(15)); // Set token
                                                                                     // expiry to 15
                                                                                     // minutes

        Authentication savedUser = authenticationRepository.save(userAuthentication);

        if (savedUser != null && savedUser.getId() != null) {
            // Send confirmation email
            String appUrl = "http://localhost:8080"; // Replace with your actual app URL
            sendConfirmationEmail(savedUser, appUrl, resetToken);
            // Return success response
            return ResponseEntity.ok("User registered successfully");
        } else {
            // Return error response
            return ResponseEntity.status(500).body("Registration failed");
        }

    }

    public void sendConfirmationEmail(Authentication authentication, String appUrl,
            String resetToken) {
        // Generate confirmation link
        String confirmationLink = appUrl + "/confirm-email?token=" + resetToken;

        // Use JavaMailSender to send the email with the link
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(authentication.getEmail());
        message.setSubject("Email Confirmation");
        message.setText(
                "Please confirm your email by clicking the following link: " + confirmationLink);

    }

}
