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
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.dinkybell.ecommerce.authentication.entity.UserAuthentication;
import com.dinkybell.ecommerce.authentication.repository.UserAuthenticationRepository;
import com.dinkybell.ecommerce.authentication.util.JwtUtil;

@ExtendWith(MockitoExtension.class)
class UserAuthenticationServiceRegistrationTest {

    @Mock
    private UserAuthenticationRepository authenticationRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JavaMailSender mailSender;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private TokenBlacklistService tokenBlacklistService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @InjectMocks
    private UserAuthenticationService service;

    @Test
    void registerUser_newEmail_savesUserAndSendsConfirmationEmail() {
        String email = "user@example.com";
        String password = "secret";
        String hashed = "hashed-secret";

        when(authenticationRepository.existsByEmail(email)).thenReturn(false);
        when(passwordEncoder.encode(password)).thenReturn(hashed);
        when(authenticationRepository.save(any(UserAuthentication.class))).thenAnswer(invocation -> {
            UserAuthentication saved = invocation.getArgument(0);
            saved.setId(1L);
            return saved;
        });

        ResponseEntity<?> response = service.registerUser(email, password);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody())
                .isEqualTo("Please confirm your email, check your inbox for the confirmation link.");

        ArgumentCaptor<UserAuthentication> captor = ArgumentCaptor.forClass(UserAuthentication.class);
        verify(authenticationRepository, times(1)).save(captor.capture());
        UserAuthentication savedUser = captor.getValue();
        assertThat(savedUser.getEmail()).isEqualTo(email);
        assertThat(savedUser.getPassword()).isEqualTo(hashed);
        assertThat(savedUser.getEmailConfirmToken()).isNotNull();
        assertThat(savedUser.getEmailConfirmTokenExpiry()).isNotNull();
        verify(mailSender, times(1)).send(any(SimpleMailMessage.class));
    }

    @Test
    void registerUser_existingEnabledEmail_returnsBadRequest() {
        String email = "user@example.com";
        String password = "secret";
        UserAuthentication existing = new UserAuthentication();
        existing.setEmail(email);
        existing.setEnabled(true);

        when(authenticationRepository.existsByEmail(email)).thenReturn(true);
        when(authenticationRepository.findByEmail(email)).thenReturn(java.util.Optional.of(existing));

        ResponseEntity<?> response = service.registerUser(email, password);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isEqualTo("Email already exists");
        verify(authenticationRepository, never()).save(any(UserAuthentication.class));
        verify(mailSender, never()).send(any(SimpleMailMessage.class));
    }

    // This test covers the case where an email exists but is not enabled, so it should resend the confirmation email.
    // It verifies that the user is updated with a new token and that an email is sent.
    @Test
    void registerUser_existingNotEnabledEmail_resendsConfirmation() {
        String email = "user@example.com";
        String password = "secret";
        String hashed = "hashed-secret";
        UserAuthentication existing = new UserAuthentication();
        existing.setEmail(email);
        existing.setEnabled(false);

        when(authenticationRepository.existsByEmail(email)).thenReturn(true);
        when(authenticationRepository.findByEmail(email)).thenReturn(java.util.Optional.of(existing));
        when(passwordEncoder.encode(password)).thenReturn(hashed);
        when(authenticationRepository.save(any(UserAuthentication.class))).thenAnswer(invocation -> {
            UserAuthentication saved = invocation.getArgument(0);
            saved.setId(2L);
            return saved;
        });

        ResponseEntity<?> response = service.registerUser(email, password);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        ArgumentCaptor<UserAuthentication> captor = ArgumentCaptor.forClass(UserAuthentication.class);
        verify(authenticationRepository, times(1)).save(captor.capture());
        UserAuthentication savedUser = captor.getValue();
        assertThat(savedUser.getEmail()).isEqualTo(email);
        assertThat(savedUser.getPassword()).isEqualTo(hashed);
        assertThat(savedUser.getEmailConfirmToken()).isNotNull();
        assertThat(savedUser.getEmailConfirmTokenExpiry()).isNotNull();
        verify(mailSender, times(1)).send(any(SimpleMailMessage.class));
    }

    @Test
    void saveUser_whenEmailSendingFails_returnsBadRequest() {
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
                .when(mailSender).send(any(SimpleMailMessage.class));

        ResponseEntity<String> response = service.saveUser(user);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).contains("Email authentication failed");
    }

    @Test
    void saveUser_whenSaveReturnsNullId_returnsServerError() {
        UserAuthentication user = new UserAuthentication();
        user.setEmail("user@example.com");
        user.setEmailConfirmToken("token");
        user.setEmailConfirmTokenExpiry(LocalDateTime.now().plusMinutes(5));

        UserAuthentication saved = new UserAuthentication();
        saved.setEmail("user@example.com");
        when(authenticationRepository.save(any(UserAuthentication.class))).thenReturn(saved);

        ResponseEntity<String> response = service.saveUser(user);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody()).isEqualTo("Registration failed");
        verify(mailSender, never()).send(any(SimpleMailMessage.class));
    }
}
