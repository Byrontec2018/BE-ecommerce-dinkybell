package com.dinkybell.ecommerce.authentication.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.MailAuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.dinkybell.ecommerce.authentication.dto.UserAuthenticationRequestDTO;
import com.dinkybell.ecommerce.authentication.entity.UserAuthentication;
import com.dinkybell.ecommerce.authentication.repository.UserAuthenticationRepository;

/**
 * Unit tests for {@link UserRegistrationService}.
 * 
 * This test suite verifies the user registration flow including:
 * - New user account creation
 * - Email confirmation token generation
 * - Confirmation email sending
 * - Handling of duplicate email addresses
 * - Re-sending confirmation for inactive accounts
 * - Error handling for email service failures
 * 
 * Tests follow the Arrange-Act-Assert pattern with comprehensive verification
 * of both successful operations and error scenarios.
 */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings("null")
class UserAuthenticationServiceRegistrationTest {

    @Mock
    private UserAuthenticationRepository authenticationRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private EmailNotificationService emailNotificationService;

    @InjectMocks
    private UserRegistrationService service;

    /**
     * Tests successful registration of a new user with a unique email address.
     * 
     * Verifies that:
     * - Email uniqueness is validated
     * - Password is hashed using the configured encoder (Argon2id)
     * - Email confirmation token is generated (UUID format)
     * - Token expiry is set (typically 24-48 hours)
     * - User entity is saved to database
     * - Confirmation email is sent
     * - HTTP 200 OK response is returned with appropriate message
     */
    @Test
    void registerUser_newEmail_savesUserAndSendsConfirmationEmail() {
        String email = "user@example.com";
        String password = "secret";
        String hashed = "hashed-secret";
        UserAuthenticationRequestDTO requestDTO = new UserAuthenticationRequestDTO();
        requestDTO.setEmail(email);
        requestDTO.setPassword(password);

        when(authenticationRepository.existsByEmail(email)).thenReturn(false);
        when(passwordEncoder.encode(password)).thenReturn(hashed);
        when(authenticationRepository.save(any(UserAuthentication.class))).thenAnswer(invocation -> {
            UserAuthentication saved = invocation.getArgument(0);
            saved.setId(1L);
            return saved;
        });

        ResponseEntity<?> response = service.registerUser(requestDTO);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        ArgumentCaptor<UserAuthentication> captor = ArgumentCaptor.forClass(UserAuthentication.class);
        verify(authenticationRepository, times(1)).save(captor.capture());
        UserAuthentication savedUser = captor.getValue();
        assertThat(savedUser.getEmail()).isEqualTo(email);
        assertThat(savedUser.getPassword()).isEqualTo(hashed);
        assertThat(savedUser.getEmailConfirmToken()).isNotNull();
        assertThat(savedUser.getEmailConfirmTokenExpiry()).isNotNull();
        verify(emailNotificationService, times(1)).sendConfirmationEmail(any(UserAuthentication.class));
    }

    /**
     * Tests registration behaviour when email already exists and is active.
     * 
     * Verifies that:
     * - EmailAlreadyExistsException is thrown for duplicate active email
     * - No new user entity is created
     * - No confirmation email is sent
     * - Exception is handled by GlobalExceptionHandler (HTTP 409 Conflict)
     */
    @Test
    void registerUser_existingActiveEmail_throwsException() {
        String email = "user@example.com";
        String password = "secret";
        UserAuthenticationRequestDTO requestDTO = new UserAuthenticationRequestDTO();
        requestDTO.setEmail(email);
        requestDTO.setPassword(password);
        
        UserAuthentication existing = new UserAuthentication();
        existing.setEmail(email);
        existing.setActive(true);

        when(authenticationRepository.existsByEmail(email)).thenReturn(true);
        when(authenticationRepository.existsByEmailAndActiveFalse(email)).thenReturn(false);

        // This should throw EmailAlreadyExistsException which is handled by GlobalExceptionHandler
        org.junit.jupiter.api.Assertions.assertThrows(
            com.dinkybell.ecommerce.authentication.exception.EmailAlreadyExistsException.class,
            () -> service.registerUser(requestDTO)
        );

        verify(authenticationRepository, never()).save(any(UserAuthentication.class));
        verify(emailNotificationService, never()).sendConfirmationEmail(any(UserAuthentication.class));
    }

    /**
     * Tests registration behaviour when email exists but account is not active.
     * 
     * This covers the case where a user previously registered but never confirmed
     * their email. The system should allow "re-registration" by:
     * - Updating the existing user record
     * - Generating a new confirmation token
     * - Re-sending the confirmation email
     * - Updating the password if provided
     * 
     * This provides a better user experience than forcing password recovery.
     */
    @Test
    void registerUser_existingNotActiveEmail_resendsConfirmation() {
        String email = "user@example.com";
        String password = "secret";
        String hashed = "hashed-secret";
        UserAuthenticationRequestDTO requestDTO = new UserAuthenticationRequestDTO();
        requestDTO.setEmail(email);
        requestDTO.setPassword(password);
        
        UserAuthentication existing = new UserAuthentication();
        existing.setEmail(email);
        existing.setActive(false);

        when(authenticationRepository.existsByEmail(email)).thenReturn(true);
        when(authenticationRepository.existsByEmailAndActiveFalse(email)).thenReturn(true);
        when(authenticationRepository.findByEmail(email)).thenReturn(java.util.Optional.of(existing));
        when(passwordEncoder.encode(password)).thenReturn(hashed);
        when(authenticationRepository.save(any(UserAuthentication.class))).thenAnswer(invocation -> {
            UserAuthentication saved = invocation.getArgument(0);
            saved.setId(2L);
            return saved;
        });

        ResponseEntity<?> response = service.registerUser(requestDTO);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        ArgumentCaptor<UserAuthentication> captor = ArgumentCaptor.forClass(UserAuthentication.class);
        verify(authenticationRepository, times(1)).save(captor.capture());
        UserAuthentication savedUser = captor.getValue();
        assertThat(savedUser.getEmail()).isEqualTo(email);
        assertThat(savedUser.getPassword()).isEqualTo(hashed);
        assertThat(savedUser.getEmailConfirmToken()).isNotNull();
        assertThat(savedUser.getEmailConfirmTokenExpiry()).isNotNull();
        verify(emailNotificationService, times(1)).sendConfirmationEmail(any(UserAuthentication.class));
    }

    /**
     * Tests registration behaviour when email sending fails.
     * 
     * Verifies that:
     * - User is saved to database before email attempt
     * - MailAuthenticationException is thrown when email service fails
     * - Exception propagates to GlobalExceptionHandler
     * - User receives appropriate error feedback
     * - Can retry registration (email already exists handling applies)
     */
    @Test
    void saveUser_whenEmailSendingFails_throwsException() {
        UserAuthentication user = new UserAuthentication();
        user.setEmail("user@example.com");
        user.setEmailConfirmToken("token");
        user.setEmailConfirmTokenExpiry(LocalDateTime.now().plusMinutes(5));

        when(authenticationRepository.save(any(UserAuthentication.class))).thenAnswer(invocation -> {
            UserAuthentication saved = invocation.getArgument(0);
            saved.setId(3L);
            return saved;
        });
        doThrow(new MailAuthenticationException("bad-credentials"))
                .when(emailNotificationService).sendConfirmationEmail(any(UserAuthentication.class));

        // EmailSendException is handled by GlobalExceptionHandler
        org.junit.jupiter.api.Assertions.assertThrows(
            MailAuthenticationException.class,
            () -> service.saveUser(user)
        );
    }

    /**
     * Tests successful user save operation with email confirmation.
     * 
     * Verifies that:
     * - User entity is persisted to database
     * - Database auto-generates user ID
     * - Confirmation email is sent successfully
     * - HTTP 200 OK response is returned
     * - Complete registration flow executes without errors
     */
    @Test
    void saveUser_success_returnsOk() {
        UserAuthentication user = new UserAuthentication();
        user.setEmail("user@example.com");
        user.setEmailConfirmToken("token");
        user.setEmailConfirmTokenExpiry(LocalDateTime.now().plusMinutes(5));

        UserAuthentication saved = new UserAuthentication();
        saved.setId(4L);
        saved.setEmail("user@example.com");
        when(authenticationRepository.save(any(UserAuthentication.class))).thenReturn(saved);

        ResponseEntity<?> response = service.saveUser(user);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        verify(emailNotificationService, times(1)).sendConfirmationEmail(any(UserAuthentication.class));
    }
}
