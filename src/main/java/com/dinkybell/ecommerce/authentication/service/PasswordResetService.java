package com.dinkybell.ecommerce.authentication.service;

import java.time.LocalDateTime;

import com.dinkybell.ecommerce.shared.util.SecureTokenGenerator;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.dinkybell.ecommerce.authentication.dto.PasswordResetConfirmDTO;
import com.dinkybell.ecommerce.authentication.dto.PasswordResetRequestDTO;
import com.dinkybell.ecommerce.authentication.entity.UserAuthentication;
import com.dinkybell.ecommerce.authentication.exception.EmailSendException;
import com.dinkybell.ecommerce.authentication.exception.TokenExpiredException;
import com.dinkybell.ecommerce.authentication.repository.UserAuthenticationRepository;
import com.dinkybell.ecommerce.shared.dto.APIResponseDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Service responsible for password reset flows.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordResetService {

    private final UserAuthenticationRepository authenticationRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailNotificationService emailNotificationService;

    /**
     * Initiates the password reset process for a user.
     * 
     * This method generates a reset token and sends it via email. For security,
     * it always returns a success message even if the email doesn't exist, to
     * prevent email enumeration attacks. Exceptions are handled by GlobalExceptionHandler.
     *
     * @param request DTO containing the user's email address
     * @return ResponseEntity with success message
     * @throws EmailSendException if the email fails to send
     */
    public ResponseEntity<APIResponseDTO<Object>> requestPasswordReset(PasswordResetRequestDTO request) {

        String email = request.getEmail();

        log.info("Password reset requested for email: {}", email);

        UserAuthentication authentication = authenticationRepository.findByEmail(email).orElse(null);

        if (authentication == null) {
            log.info("Password reset requested for non-existent email: {}", email);
            return ApiResponseFactory.buildResponse(HttpStatus.OK,
                    "If your email exists in our system, you will receive a password reset link",
                    null, null);
        }

        String resetToken = SecureTokenGenerator.generateShortToken(); // 128-bit token for password reset (15 min validity)

        authentication.setResetPasswordToken(resetToken);
        authentication.setResetPasswordTokenExpiry(LocalDateTime.now().plusMinutes(15));

        authenticationRepository.save(authentication);

        String messageResponse = emailNotificationService.sendPasswordResetEmail(authentication, resetToken);

        if (messageResponse.contains("Error")) {
            log.error("Failed to send password reset email: {}", messageResponse);
            throw new EmailSendException("Failed to send password reset email. Please try again later.");
        }

        return ApiResponseFactory.buildResponse(HttpStatus.OK,
                "If your email exists in our system, you will receive a password reset link",
                null, null);

    }

    /**
     * Validates the reset token and updates the user's password.
     * 
     * This method verifies the reset token hasn't expired and updates the user's
     * password with the new hashed value. Exceptions are handled by GlobalExceptionHandler.
     *
     * @param resetData DTO containing the token and new password
     * @return ResponseEntity with success message
     * @throws TokenExpiredException if the reset token is invalid or expired
     */
    public ResponseEntity<APIResponseDTO<Object>> resetPassword(PasswordResetConfirmDTO resetData) {        

        UserAuthentication authentication = authenticationRepository.findByResetPasswordToken(resetData.getToken());

        if (authentication == null
                || authentication.getResetPasswordTokenExpiry() == null
                || authentication.getResetPasswordTokenExpiry().isBefore(LocalDateTime.now())) {
            log.warn("Invalid or expired password reset token used: {}", resetData.getToken());
            throw new TokenExpiredException("Invalid or expired reset token. Please request a new password reset.");
        }

        String hashedPassword = passwordEncoder.encode(resetData.getNewPassword());

        authentication.setPassword(hashedPassword);
        authentication.setResetPasswordToken(null);
        authentication.setResetPasswordTokenExpiry(null);

        authenticationRepository.save(authentication);

        log.info("Password successfully reset for user: {}", authentication.getEmail());
        return ApiResponseFactory.buildResponse(HttpStatus.OK,
                "Password successfully reset. You can now log in with your new password.",
                null, null);

    }
    
}
