package com.dinkybell.ecommerce.services;

import java.time.LocalDateTime;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.dinkybell.ecommerce.entities.UserAuthentication;
import com.dinkybell.ecommerce.repositories.UserAuthenticationRepository;

@Service
public class UserAuthenticationService {

    @Autowired
    UserAuthenticationRepository authenticationRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    private JavaMailSender mailSender;

    public ResponseEntity<?> registerUser(String email, String password) {

        // Check if email already exists
        if (authenticationRepository.existsByEmail(email)) {
            return ResponseEntity.badRequest().body("Email already exists");
        }

        // Create hashed password
        String hashedPassword = passwordEncoder.encode(password);

        // Generate confirm e-mail token
        String emailConfirmToken = UUID.randomUUID().toString();

        UserAuthentication userAuthentication = new UserAuthentication();
        userAuthentication.setEmail(email);
        userAuthentication.setPassword(hashedPassword);
        userAuthentication.setEmailConfirmToken(emailConfirmToken);
        userAuthentication.setEmailConfirmTokenExpiry(LocalDateTime.now().plusMinutes(15)); // Set
                                                                                            // token
                                                                                            // expiry
                                                                                            // to 15
                                                                                            // minutes

        try {

            UserAuthentication savedUser = authenticationRepository.save(userAuthentication);

            if (savedUser != null && savedUser.getId() != null) {

                // Send confirmation email
                String messageResponse = sendConfirmationEmail(savedUser, emailConfirmToken);

                if (messageResponse.contains("Error")) {
                    return ResponseEntity.badRequest().body(messageResponse);
                }

                // Return success response
                return ResponseEntity.ok(
                        "Please confirm your email, check your inbox for the confirmation link.");
            } else {
                // Return error response
                return ResponseEntity.status(500).body("Registration failed");
            }

        } catch (Exception e) {

            e.printStackTrace();
            return ResponseEntity.status(500).body("Registration failed: " + e.getMessage());
        }

    }

    public String sendConfirmationEmail(UserAuthentication authentication,
            String emailConfirmToken) {

        try {
            // Generate confirmation link
            String confirmationLink =
                    "http://192.162.1.108:8080/confirm-email?token=" + emailConfirmToken;

            // Use JavaMailSender to send the email with the link
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom("support@dinkybell.com");
            message.setTo(authentication.getEmail());
            message.setSubject("Email Confirmation");
            message.setText("Please confirm your email by clicking the following link: "
                    + confirmationLink);
            // Send the email
            mailSender.send(message);
            System.out.println("E-mail inviata correttamente");
            return "Confirmation email sent successfully";
        } catch (org.springframework.mail.MailAuthenticationException e) {
            return "Error: Email authentication failed - check email credentials";
        } catch (org.springframework.mail.MailSendException e) {
            return "Error: Could not send email - check SMTP configuration";
        } catch (Exception e) {
            return "Error sending confirmation email: " + e.getMessage();
        }

    }

    public ResponseEntity<?> confirmEmail(String emailConfirmToken) {
        // Find user by reset token
        UserAuthentication authentication =
                authenticationRepository.findByEmailConfirmToken(emailConfirmToken);
        if (authentication == null
                || authentication.getEmailConfirmTokenExpiry().isBefore(LocalDateTime.now())) {
            return ResponseEntity.badRequest().body("Invalid or expired token");
        }

        // Confirm email
        authentication.setEnabled(true);
        authentication.setEmailConfirmedAt(LocalDateTime.now());
        authentication.setEmailConfirmToken(null); // Clear reset token after confirmation
        authentication.setEmailConfirmTokenExpiry(null); // Clear reset token expiry
        authenticationRepository.save(authentication);

        return ResponseEntity.ok("Email confirmed successfully");
    }

    public ResponseEntity<?> login(String email, String password) {
        // Find user by email
        UserAuthentication authentication =
                authenticationRepository.findByEmail(email).orElse(null);
        if (authentication == null) {
            return ResponseEntity.badRequest().body("Invalid email or password");
        }

        // Check password
        if (!passwordEncoder.matches(password, authentication.getPassword())) {
            return ResponseEntity.badRequest().body("Invalid email or password");
        }

        // Check if email is confirmed
        if (!authentication.isEnabled()) {
            return ResponseEntity.badRequest().body("Email not confirmed");
        }

        // Set last login time
        authentication.setLastLogin(LocalDateTime.now());

        // Generate JWT token
        // .........

        // Save user
        authenticationRepository.save(authentication);

        // Return success response - RETURN JWT TOKEN HERE
        return ResponseEntity.ok("Login successful");
    }

}
