package com.dinkybell.ecommerce.authentication.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Date;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.dinkybell.ecommerce.authentication.dto.UserAuthenticationRequestDTO;
import com.dinkybell.ecommerce.authentication.entity.RefreshToken;
import com.dinkybell.ecommerce.authentication.entity.UserAuthentication;
import com.dinkybell.ecommerce.authentication.exception.InvalidTokenException;
import com.dinkybell.ecommerce.authentication.exception.TokenAlreadyInvalidatedException;
import com.dinkybell.ecommerce.authentication.repository.UserAuthenticationRepository;
import com.dinkybell.ecommerce.authentication.util.JwtUtil;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Unit tests for {@link UserLoginService}.
 * 
 * This test suite verifies the behaviour of the login and logout operations,
 * including authentication flow, JWT token generation, refresh token creation,
 * token blacklisting, and various error scenarios.
 * 
 * Tests follow the Arrange-Act-Assert pattern with Mockito for dependency isolation.
 */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings("null")
class UserLoginServiceTest {

    @Mock
    private UserAuthenticationRepository authenticationRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private TokenBlacklistService tokenBlacklistService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private UserRegistrationService userRegistrationService;

    @Mock
    private HttpServletRequest request;

    @InjectMocks
    private UserLoginService service;

    /**
     * Tests successful login with valid credentials and an active user account.
     * 
     * Verifies that:
     * - Authentication succeeds with correct email and password
     * - JWT access token is generated
     * - Refresh token is created
     * - User's last login timestamp is updated
     * - HTTP 200 OK response is returned with token data
     */
    @Test
    void loginUser_validCredentialsActiveUser_returnsJwtResponse() {
        String email = "user@example.com";
        String password = "password123";
        String hashedPassword = "hashed-password";
        String accessToken = "jwt-access-token";
        String refreshTokenString = "refresh-token-uuid";
        
        UserAuthenticationRequestDTO loginRequest = new UserAuthenticationRequestDTO();
        loginRequest.setEmail(email);
        loginRequest.setPassword(password);

        UserAuthentication auth = new UserAuthentication();
        auth.setId(1L);
        auth.setEmail(email);
        auth.setPassword(hashedPassword);
        auth.setActive(true);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(refreshTokenString);

        Date expirationDate = new Date(System.currentTimeMillis() + 300000);

        when(authenticationRepository.findByEmail(email)).thenReturn(Optional.of(auth));
        when(passwordEncoder.matches(password, hashedPassword)).thenReturn(true);
        when(jwtUtil.generateToken(auth)).thenReturn(accessToken);
        when(refreshTokenService.createRefreshToken(anyLong(), any(HttpServletRequest.class)))
                .thenReturn(refreshToken);
        when(jwtUtil.extractExpirationDate(accessToken)).thenReturn(expirationDate);

        ResponseEntity<?> response = service.loginUser(loginRequest, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();

        verify(authenticationRepository, times(1)).save(any(UserAuthentication.class));
        verify(refreshTokenService, times(1)).createRefreshToken(1L, request);

        ArgumentCaptor<UserAuthentication> captor = ArgumentCaptor.forClass(UserAuthentication.class);
        verify(authenticationRepository).save(captor.capture());
        assertThat(captor.getValue().getLastLogin()).isNotNull();
    }

    /**
     * Tests login behaviour when the email address doesn't exist in the system.
     * 
     * Verifies that:
     * - BadCredentialsException is thrown for non-existent email
     * - No user data is saved to the database
     * - No JWT token is generated
     */
    @Test
    void loginUser_invalidEmail_throwsBadCredentialsException() {
        String email = "nonexistent@example.com";
        String password = "password123";

        UserAuthenticationRequestDTO loginRequest = new UserAuthenticationRequestDTO();
        loginRequest.setEmail(email);
        loginRequest.setPassword(password);

        when(authenticationRepository.findByEmail(email)).thenReturn(Optional.empty());

        org.junit.jupiter.api.Assertions.assertThrows(
                BadCredentialsException.class,
                () -> service.loginUser(loginRequest, request)
        );

        verify(authenticationRepository, never()).save(any(UserAuthentication.class));
        verify(jwtUtil, never()).generateToken(any(UserAuthentication.class));
    }

    /**
     * Tests login behaviour when the password doesn't match the stored hash.
     * 
     * Verifies that:
     * - BadCredentialsException is thrown for incorrect password
     * - No JWT token is generated even though email exists
     */
    @Test
    void loginUser_invalidPassword_throwsBadCredentialsException() {
        String email = "user@example.com";
        String password = "wrongpassword";
        String hashedPassword = "hashed-password";

        UserAuthenticationRequestDTO loginRequest = new UserAuthenticationRequestDTO();
        loginRequest.setEmail(email);
        loginRequest.setPassword(password);

        UserAuthentication auth = new UserAuthentication();
        auth.setEmail(email);
        auth.setPassword(hashedPassword);
        auth.setActive(true);

        when(authenticationRepository.findByEmail(email)).thenReturn(Optional.of(auth));
        when(passwordEncoder.matches(password, hashedPassword)).thenReturn(false);

        org.junit.jupiter.api.Assertions.assertThrows(
                BadCredentialsException.class,
                () -> service.loginUser(loginRequest, request)
        );

        verify(jwtUtil, never()).generateToken(any(UserAuthentication.class));
    }

    /**
     * Tests login behaviour when attempting to access an inactive account.
     * 
     * Verifies that:
     * - Login is prevented for accounts that haven't confirmed their email
     * - A new confirmation token is generated
     * - Confirmation email is resent to the user
     * - No JWT token is generated until email is confirmed
     */
    @Test
    void loginUser_inactiveAccount_resendsConfirmationEmail() {
        String email = "inactive@example.com";
        String password = "password123";
        String hashedPassword = "hashed-password";

        UserAuthenticationRequestDTO loginRequest = new UserAuthenticationRequestDTO();
        loginRequest.setEmail(email);
        loginRequest.setPassword(password);

        UserAuthentication auth = new UserAuthentication();
        auth.setEmail(email);
        auth.setPassword(hashedPassword);
        auth.setActive(false);

        when(authenticationRepository.findByEmail(email)).thenReturn(Optional.of(auth));
        when(passwordEncoder.matches(password, hashedPassword)).thenReturn(true);
        when(userRegistrationService.saveUser(any(UserAuthentication.class)))
                .thenReturn(ResponseEntity.ok().build());

        ResponseEntity<?> response = service.loginUser(loginRequest, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        verify(userRegistrationService, times(1)).createConfirmationToken(auth);
        verify(userRegistrationService, times(1)).saveUser(auth);
        verify(jwtUtil, never()).generateToken(any(UserAuthentication.class));
    }

    /**
     * Tests successful logout with a valid JWT token.
     * 
     * Verifies that:
     * - JWT token is extracted from Authorization header
     * - Token JTI is added to the blacklist
     * - Token expiration date is recorded for cleanup
     * - HTTP 200 OK response is returned
     */
    @Test
    void logoutUser_validToken_blacklistsToken() {
        String token = "valid-jwt-token";
        String jti = "jwt-id-123";
        String email = "user@example.com";
        Date expiryDate = new Date(System.currentTimeMillis() + 300000);

        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(jwtUtil.extractJti(token)).thenReturn(jti);
        when(tokenBlacklistService.isBlacklisted(jti)).thenReturn(false);
        when(jwtUtil.extractExpirationDate(token)).thenReturn(expiryDate);
        when(jwtUtil.extractEmail(token)).thenReturn(email);

        ResponseEntity<?> response = service.logoutUser(request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        verify(tokenBlacklistService, times(1)).blacklistToken(jti, expiryDate);
    }

    /**
     * Tests logout behaviour when attempting to use an already blacklisted token.
     * 
     * Verifies that:
     * - TokenAlreadyInvalidatedException is thrown for duplicate logout
     * - Token is not added to blacklist again (idempotent operation)
     */
    @Test
    void logoutUser_alreadyBlacklistedToken_throwsTokenAlreadyInvalidatedException() {
        String token = "already-blacklisted-token";
        String jti = "jwt-id-456";

        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(jwtUtil.extractJti(token)).thenReturn(jti);
        when(tokenBlacklistService.isBlacklisted(jti)).thenReturn(true);

        org.junit.jupiter.api.Assertions.assertThrows(
                TokenAlreadyInvalidatedException.class,
                () -> service.logoutUser(request)
        );

        verify(tokenBlacklistService, never()).blacklistToken(anyString(), any(Date.class));
    }

    /**
     * Tests logout behaviour when the Authorization header is missing.
     * 
     * Verifies that:
     * - InvalidTokenException is thrown when header is null
     * - No token blacklisting occurs
     */
    @Test
    void logoutUser_noAuthorizationHeader_throwsInvalidTokenException() {
        when(request.getHeader("Authorization")).thenReturn(null);

        org.junit.jupiter.api.Assertions.assertThrows(
                InvalidTokenException.class,
                () -> service.logoutUser(request)
        );

        verify(tokenBlacklistService, never()).blacklistToken(anyString(), any(Date.class));
    }

    /**
     * Tests logout behaviour when the Authorization header has incorrect format.
     * 
     * Verifies that:
     * - InvalidTokenException is thrown for non-Bearer format
     * - No token blacklisting occurs
     */
    @Test
    void logoutUser_invalidHeaderFormat_throwsInvalidTokenException() {
        when(request.getHeader("Authorization")).thenReturn("InvalidFormat token");

        org.junit.jupiter.api.Assertions.assertThrows(
                InvalidTokenException.class,
                () -> service.logoutUser(request)
        );

        verify(tokenBlacklistService, never()).blacklistToken(anyString(), any(Date.class));
    }

    /**
     * Tests logout behaviour when the JWT token cannot be parsed.
     * 
     * Verifies that:
     * - InvalidTokenException is thrown for malformed tokens
     * - Token parsing errors are wrapped appropriately
     * - No token blacklisting occurs
     */
    @Test
    void logoutUser_malformedToken_throwsInvalidTokenException() {
        String token = "malformed-token";

        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(jwtUtil.extractJti(token)).thenThrow(new RuntimeException("Token parsing failed"));

        org.junit.jupiter.api.Assertions.assertThrows(
                InvalidTokenException.class,
                () -> service.logoutUser(request)
        );

        verify(tokenBlacklistService, never()).blacklistToken(anyString(), any(Date.class));
    }
}
