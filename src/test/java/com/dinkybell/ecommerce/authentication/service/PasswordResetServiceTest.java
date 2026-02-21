package com.dinkybell.ecommerce.authentication.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.dinkybell.ecommerce.authentication.dto.PasswordResetConfirmDTO;
import com.dinkybell.ecommerce.authentication.dto.PasswordResetRequestDTO;
import com.dinkybell.ecommerce.authentication.entity.UserAuthentication;
import com.dinkybell.ecommerce.authentication.exception.EmailSendException;
import com.dinkybell.ecommerce.authentication.exception.TokenExpiredException;
import com.dinkybell.ecommerce.authentication.repository.UserAuthenticationRepository;
import com.dinkybell.ecommerce.shared.dto.APIResponseDTO;

/**
 * Unit tests for {@link PasswordResetService}.
 * 
 * This test suite verifies the password reset flow, including request initiation,
 * email sending, token validation, and password update operations.
 * 
 * Tests cover both successful scenarios and various failure modes to ensure
 * robust error handling and security measures (e.g., preventing email enumeration).
 */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings("null")
class PasswordResetServiceTest {

    @Mock
    private UserAuthenticationRepository authenticationRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private EmailNotificationService emailNotificationService;

    @InjectMocks
    private PasswordResetService service;

    /**
     * Tests password reset request for an existing email address.
     * 
     * Verifies that:
     * - Reset token is generated and stored with 15-minute expiry
     * - Password reset email is sent successfully
     * - HTTP 200 OK response is returned (generic message for security)
     * - Token expiration time is set correctly in the future
     */
    @Test
    void requestPasswordReset_existingEmail_sendsResetEmailAndReturnsSuccess() {
        String email = "user@example.com";
        PasswordResetRequestDTO requestDTO = new PasswordResetRequestDTO();
        requestDTO.setEmail(email);

        UserAuthentication auth = new UserAuthentication();
        auth.setEmail(email);

        when(authenticationRepository.findByEmail(email)).thenReturn(Optional.of(auth));
        when(emailNotificationService.sendPasswordResetEmail(any(UserAuthentication.class), anyString()))
                .thenReturn("Email sent successfully");

        ResponseEntity<APIResponseDTO<Object>> response = service.requestPasswordReset(requestDTO);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        ArgumentCaptor<UserAuthentication> captor = ArgumentCaptor.forClass(UserAuthentication.class);
        verify(authenticationRepository, times(1)).save(captor.capture());

        UserAuthentication savedAuth = captor.getValue();
        assertThat(savedAuth.getResetPasswordToken()).isNotNull();
        assertThat(savedAuth.getResetPasswordTokenExpiry()).isNotNull();
        assertThat(savedAuth.getResetPasswordTokenExpiry()).isAfter(LocalDateTime.now());

        verify(emailNotificationService, times(1)).sendPasswordResetEmail(any(UserAuthentication.class), anyString());
    }

    /**
     * Tests password reset request for a non-existent email address.
     * 
     * Verifies that:
     * - Same generic success message is returned (prevents email enumeration attacks)
     * - No database operations occur
     * - No email is sent
     * - Response appears identical to valid email case for security
     */
    @Test
    void requestPasswordReset_nonExistentEmail_returnsSuccessWithoutSendingEmail() {
        String email = "nonexistent@example.com";
        PasswordResetRequestDTO requestDTO = new PasswordResetRequestDTO();
        requestDTO.setEmail(email);

        when(authenticationRepository.findByEmail(email)).thenReturn(Optional.empty());

        ResponseEntity<APIResponseDTO<Object>> response = service.requestPasswordReset(requestDTO);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        verify(authenticationRepository, never()).save(any(UserAuthentication.class));
        verify(emailNotificationService, never()).sendPasswordResetEmail(any(UserAuthentication.class), anyString());
    }

    /**
     * Tests password reset request when email sending fails.
     * 
     * Verifies that:
     * - EmailSendException is thrown when email service fails
     * - Error is propagated to GlobalExceptionHandler
     * - User receives appropriate error feedback
     */
    @Test
    void requestPasswordReset_emailSendingFails_throwsEmailSendException() {
        String email = "user@example.com";
        PasswordResetRequestDTO requestDTO = new PasswordResetRequestDTO();
        requestDTO.setEmail(email);

        UserAuthentication auth = new UserAuthentication();
        auth.setEmail(email);

        when(authenticationRepository.findByEmail(email)).thenReturn(Optional.of(auth));
        when(emailNotificationService.sendPasswordResetEmail(any(UserAuthentication.class), anyString()))
                .thenReturn("Error: Failed to send email");

        org.junit.jupiter.api.Assertions.assertThrows(
                EmailSendException.class,
                () -> service.requestPasswordReset(requestDTO)
        );
    }

    /**
     * Tests successful password reset with a valid token.
     * 
     * Verifies that:
     * - Token is validated against database
     * - Token expiry time is checked (must not be expired)
     * - New password is hashed using password encoder
     * - Password is updated in database
     * - Reset token and expiry are cleared after successful reset
     * - HTTP 200 OK response is returned
     */
    @Test
    void resetPassword_validToken_resetsPasswordSuccessfully() {
        String token = "valid-reset-token";
        String newPassword = "newPassword123";
        String hashedPassword = "hashed-new-password";

        PasswordResetConfirmDTO resetDTO = new PasswordResetConfirmDTO();
        resetDTO.setToken(token);
        resetDTO.setNewPassword(newPassword);

        UserAuthentication auth = new UserAuthentication();
        auth.setEmail("user@example.com");
        auth.setResetPasswordToken(token);
        auth.setResetPasswordTokenExpiry(LocalDateTime.now().plusMinutes(10));
        auth.setPassword("old-hashed-password");

        when(authenticationRepository.findByResetPasswordToken(token)).thenReturn(auth);
        when(passwordEncoder.encode(newPassword)).thenReturn(hashedPassword);

        ResponseEntity<APIResponseDTO<Object>> response = service.resetPassword(resetDTO);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        ArgumentCaptor<UserAuthentication> captor = ArgumentCaptor.forClass(UserAuthentication.class);
        verify(authenticationRepository, times(1)).save(captor.capture());

        UserAuthentication savedAuth = captor.getValue();
        assertThat(savedAuth.getPassword()).isEqualTo(hashedPassword);
        assertThat(savedAuth.getResetPasswordToken()).isNull();
        assertThat(savedAuth.getResetPasswordTokenExpiry()).isNull();
    }

    /**
     * Tests password reset with a token that doesn't exist in the database.
     * 
     * Verifies that:
     * - TokenExpiredException is thrown for non-existent token
     * - No password changes occur
     * - No password encoding is performed
     */
    @Test
    void resetPassword_invalidToken_throwsTokenExpiredException() {
        String token = "invalid-token";
        String newPassword = "newPassword123";

        PasswordResetConfirmDTO resetDTO = new PasswordResetConfirmDTO();
        resetDTO.setToken(token);
        resetDTO.setNewPassword(newPassword);

        when(authenticationRepository.findByResetPasswordToken(token)).thenReturn(null);

        org.junit.jupiter.api.Assertions.assertThrows(
                TokenExpiredException.class,
                () -> service.resetPassword(resetDTO)
        );

        verify(authenticationRepository, never()).save(any(UserAuthentication.class));
        verify(passwordEncoder, never()).encode(anyString());
    }

    /**
     * Tests password reset with a token that has passed its expiration time.
     * 
     * Verifies that:
     * - TokenExpiredException is thrown for expired token
     * - Password reset is rejected (security measure)
     * - User must request a new reset link
     */
    @Test
    void resetPassword_expiredToken_throwsTokenExpiredException() {
        String token = "expired-token";
        String newPassword = "newPassword123";

        PasswordResetConfirmDTO resetDTO = new PasswordResetConfirmDTO();
        resetDTO.setToken(token);
        resetDTO.setNewPassword(newPassword);

        UserAuthentication auth = new UserAuthentication();
        auth.setEmail("user@example.com");
        auth.setResetPasswordToken(token);
        auth.setResetPasswordTokenExpiry(LocalDateTime.now().minusMinutes(10)); // Expired

        when(authenticationRepository.findByResetPasswordToken(token)).thenReturn(auth);

        org.junit.jupiter.api.Assertions.assertThrows(
                TokenExpiredException.class,
                () -> service.resetPassword(resetDTO)
        );

        verify(authenticationRepository, never()).save(any(UserAuthentication.class));
        verify(passwordEncoder, never()).encode(anyString());
    }

    /**
     * Tests password reset with a token that has null expiration time.
     * 
     * Verifies that:
     * - TokenExpiredException is thrown when expiry is null
     * - Invalid token state is properly handled
     * - No password changes occur
     */
    @Test
    void resetPassword_nullTokenExpiry_throwsTokenExpiredException() {
        String token = "token-with-null-expiry";
        String newPassword = "newPassword123";

        PasswordResetConfirmDTO resetDTO = new PasswordResetConfirmDTO();
        resetDTO.setToken(token);
        resetDTO.setNewPassword(newPassword);

        UserAuthentication auth = new UserAuthentication();
        auth.setEmail("user@example.com");
        auth.setResetPasswordToken(token);
        auth.setResetPasswordTokenExpiry(null);

        when(authenticationRepository.findByResetPasswordToken(token)).thenReturn(auth);

        org.junit.jupiter.api.Assertions.assertThrows(
                TokenExpiredException.class,
                () -> service.resetPassword(resetDTO)
        );

        verify(authenticationRepository, never()).save(any(UserAuthentication.class));
    }
}
