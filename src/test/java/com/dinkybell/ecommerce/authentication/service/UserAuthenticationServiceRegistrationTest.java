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

    // This test covers the case where an email exists but is not active, so it should resend the confirmation email.
    // It verifies that the user is updated with a new token and that an email is sent.
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
