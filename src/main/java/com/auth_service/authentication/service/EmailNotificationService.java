package com.auth_service.authentication.service;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import com.auth_service.authentication.entity.UserAuthentication;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;

/**
 * Service responsible for sending authentication-related email notifications.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EmailNotificationService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    @Value("${app.email.base-url:http://localhost:8080}")
    private String baseUrl;

    /**
     * Sends a confirmation email to the user with a verification link.
     *
     * @param userAuthentication The user authentication entity
     */    
    public void sendConfirmationEmail(UserAuthentication userAuthentication) {
       
        String confirmationLink = baseUrl + "/api/v1/auth/confirm-email?token="
                + userAuthentication.getEmailConfirmToken();

        SimpleMailMessage message = new SimpleMailMessage();

        message.setFrom(fromEmail);
        message.setTo(userAuthentication.getEmail());
        message.setSubject("Email Confirmation");
        message.setText("Please confirm your email by clicking the following link: "
                + confirmationLink);

        mailSender.send(message);

        log.info("Confirmation email sent successfully to {}", userAuthentication.getEmail());        
        
    }

    /**
     * Sends a password reset email to the user with a reset link.
     *
     * @param authentication The user authentication entity
     * @param resetToken The token for password reset
     * @return Success message or error details
     */
    public String sendPasswordResetEmail(UserAuthentication authentication, String resetToken) {
        try {
            String resetLink = baseUrl + "/reset-password?token=" + resetToken;

            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(authentication.getEmail());
            message.setSubject("Password Reset Request");
            message.setText("You recently requested to reset your password. Click the following link to reset it:\n\n"
                    + resetLink + "\n\n"
                    + "This link will expire in 15 minutes.\n\n"
                    + "If you didn't request a password reset, please ignore this email or contact support if you have concerns.");

            mailSender.send(message);
            log.info("Password reset email sent successfully to {}", authentication.getEmail());
            return "Password reset email sent successfully";
        } catch (org.springframework.mail.MailAuthenticationException e) {
            log.error("Email authentication failed during password reset: {}", e.getMessage());
            return "Error: Email authentication failed - check email credentials";
        } catch (org.springframework.mail.MailSendException e) {
            log.error("Failed to send password reset email - SMTP issue: {}", e.getMessage());
            return "Error: Could not send email - check SMTP configuration";
        } catch (Exception e) {
            log.error("Unexpected error sending password reset email: {}", e.getMessage(), e);
            return "Error sending password reset email: " + e.getMessage();
        }
    }
}
