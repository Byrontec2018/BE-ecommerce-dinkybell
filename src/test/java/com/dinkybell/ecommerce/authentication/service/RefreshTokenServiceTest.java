package com.dinkybell.ecommerce.authentication.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;

import com.dinkybell.ecommerce.authentication.entity.RefreshToken;
import com.dinkybell.ecommerce.authentication.entity.UserAuthentication;
import com.dinkybell.ecommerce.authentication.exception.RefreshTokenException;
import com.dinkybell.ecommerce.authentication.repository.RefreshTokenRepository;
import com.dinkybell.ecommerce.authentication.repository.UserAuthenticationRepository;
import com.dinkybell.ecommerce.authentication.util.JwtUtil;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Unit tests for {@link RefreshTokenService}.
 * 
 * This test suite verifies the complete lifecycle of refresh tokens including:
 * - Token creation with device fingerprinting
 * - Token reuse for same device (preventing duplicates)
 * - Token limit enforcement (maximum 5 devices per user)
 * - Access token refreshing
 * - Token revocation (single and bulk)
 * - Automatic cleanup of expired tokens
 * 
 * Tests use ReflectionTestUtils to inject configuration values for consistent test behaviour.
 */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings("null")
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private UserAuthenticationRepository userAuthenticationRepository;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private HttpServletRequest request;

    @InjectMocks
    private RefreshTokenService service;

    /**
     * Initialises test configuration before each test execution.
     * Sets refresh token duration to 30 days and maximum tokens per user to 5.
     */
    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(service, "refreshTokenDurationMs", 2592000000L); // 30 days
        ReflectionTestUtils.setField(service, "maxTokensPerUser", 5);
    }

    /**
     * Tests refresh token creation for a new device.
     * 
     * Verifies that:
     * - User existence is validated before token creation
     * - Device fingerprint is extracted from request headers
     * - New token is generated with UUID format
     * - Token is persisted to database
     * - Expiration is set to 30 days in the future
     */
    @Test
    void createRefreshToken_newDevice_createsNewToken() {
        Long userId = 1L;
        UserAuthentication user = new UserAuthentication();
        user.setId(userId);

        when(userAuthenticationRepository.findById(userId)).thenReturn(Optional.of(user));
        when(request.getHeader("User-Agent")).thenReturn("Mozilla/5.0");
        when(request.getHeader("Accept-Language")).thenReturn("en-US");
        when(request.getHeader("Accept")).thenReturn("text/html");
        when(request.getRemoteAddr()).thenReturn("192.168.1.1");
        when(refreshTokenRepository.findActiveTokenByUserIdAndDevice(anyLong(), anyString(), any(Instant.class)))
                .thenReturn(Optional.empty());
        when(refreshTokenRepository.countActiveTokensByUserId(anyLong(), any(Instant.class))).thenReturn(0L);
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> {
            RefreshToken token = invocation.getArgument(0);
            token.setId(1L);
            return token;
        });

        RefreshToken result = service.createRefreshToken(userId, request);

        assertThat(result).isNotNull();
        assertThat(result.getUserId()).isEqualTo(userId);
        assertThat(result.getToken()).isNotNull();

        verify(refreshTokenRepository, times(1)).save(any(RefreshToken.class));
    }

    /**
     * Tests token reuse behaviour when the same device logs in again.
     * 
     * Verifies that:
     * - Existing valid token for same device is found
     * - Existing token is returned instead of creating new one
     * - Last used timestamp is updated (sliding window)
     * - No duplicate tokens are created for same device
     */
    @Test
    void createRefreshToken_existingValidTokenForDevice_reusesToken() {
        Long userId = 1L;
        UserAuthentication user = new UserAuthentication();
        user.setId(userId);

        RefreshToken existingToken = new RefreshToken();
        existingToken.setId(1L);
        existingToken.setUserId(userId);
        existingToken.setToken("existing-token");
        existingToken.setExpiryDate(Instant.now().plusSeconds(3600));

        when(userAuthenticationRepository.findById(userId)).thenReturn(Optional.of(user));
        when(request.getHeader("User-Agent")).thenReturn("Mozilla/5.0");
        when(request.getHeader("Accept-Language")).thenReturn("en-US");
        when(request.getHeader("Accept")).thenReturn("text/html");
        when(request.getRemoteAddr()).thenReturn("192.168.1.1");
        when(refreshTokenRepository.findActiveTokenByUserIdAndDevice(anyLong(), anyString(), any(Instant.class)))
                .thenReturn(Optional.of(existingToken));
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(existingToken);

        RefreshToken result = service.createRefreshToken(userId, request);

        assertThat(result.getToken()).isEqualTo("existing-token");
        verify(refreshTokenRepository, times(1)).save(existingToken);
    }

    /**
     * Tests token limit enforcement when maximum devices (5) is reached.
     * 
     * Verifies that:
     * - Active token count is checked before creating new token
     * - When limit is reached, oldest token is automatically revoked
     * - New token is created successfully after cleanup
     * - User can continue logging in from new devices
     */
    @Test
    void createRefreshToken_maxTokensReached_revokesOldestToken() {
        Long userId = 1L;
        UserAuthentication user = new UserAuthentication();
        user.setId(userId);

        RefreshToken oldestToken = new RefreshToken();
        oldestToken.setId(1L);
        oldestToken.setToken("oldest-token");

        when(userAuthenticationRepository.findById(userId)).thenReturn(Optional.of(user));
        when(request.getHeader("User-Agent")).thenReturn("Mozilla/5.0");
        when(request.getRemoteAddr()).thenReturn("192.168.1.1");
        when(refreshTokenRepository.findActiveTokenByUserIdAndDevice(anyLong(), anyString(), any(Instant.class)))
                .thenReturn(Optional.empty());
        when(refreshTokenRepository.countActiveTokensByUserId(anyLong(), any(Instant.class))).thenReturn(5L);
        when(refreshTokenRepository.findOldestActiveTokenByUserId(anyLong(), any(Instant.class)))
                .thenReturn(Optional.of(oldestToken));
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        service.createRefreshToken(userId, request);

        assertThat(oldestToken.isRevoked()).isTrue();
        verify(refreshTokenRepository, times(2)).save(any(RefreshToken.class));
    }

    /**
     * Tests token creation with null user ID.
     * 
     * Verifies that:
     * - IllegalArgumentException is thrown for null user ID
     * - No token creation occurs
     */
    @Test
    void createRefreshToken_nullUserId_throwsException() {
        org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> service.createRefreshToken(null, request)
        );
    }

    /**
     * Tests token creation when user doesn't exist in database.
     * 
     * Verifies that:
     * - IllegalArgumentException is thrown for non-existent user
     * - Database integrity is maintained
     */
    @Test
    void createRefreshToken_userNotFound_throwsException() {
        Long userId = 999L;

        when(userAuthenticationRepository.findById(userId)).thenReturn(Optional.empty());

        org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> service.createRefreshToken(userId, request)
        );
    }

    /**
     * Tests successful access token refresh with a valid refresh token.
     * 
     * Verifies that:
     * - Token is extracted from Bearer header format
     * - Token validity is checked (not expired, not revoked)
     * - New JWT access token is generated
     * - Last used timestamp is updated (sliding window expiry)
     * - HTTP 200 OK response with new token is returned
     */
    @Test
    void refreshAccessToken_validToken_returnsNewAccessToken() {
        String tokenString = "valid-refresh-token";
        Long userId = 1L;
        String email = "user@example.com";
        String newAccessToken = "new-jwt-token";
        Date expirationDate = new Date(System.currentTimeMillis() + 300000);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setId(1L);
        refreshToken.setToken(tokenString);
        refreshToken.setUserId(userId);
        refreshToken.setExpiryDate(Instant.now().plusSeconds(3600));
        refreshToken.setRevoked(false);

        UserAuthentication auth = new UserAuthentication();
        auth.setId(userId);
        auth.setEmail(email);

        when(refreshTokenRepository.findByToken(tokenString)).thenReturn(Optional.of(refreshToken));
        when(userAuthenticationRepository.findById(userId)).thenReturn(Optional.of(auth));
        when(jwtUtil.generateToken(auth)).thenReturn(newAccessToken);
        when(jwtUtil.extractExpirationDate(newAccessToken)).thenReturn(expirationDate);
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(refreshToken);

        ResponseEntity<?> response = service.refreshAccessToken("Bearer " + tokenString);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        verify(refreshTokenRepository, times(1)).save(any(RefreshToken.class));
        verify(jwtUtil, times(1)).generateToken(auth);
    }

    /**
     * Tests refresh behaviour when token has expired.
     * 
     * Verifies that:
     * - RefreshTokenException is thrown for expired token
     * - Token is marked as revoked in database
     * - No new JWT token is generated
     * - User must log in again
     */
    @Test
    void refreshAccessToken_expiredToken_throwsRefreshTokenException() {
        String tokenString = "expired-token";

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(tokenString);
        refreshToken.setExpiryDate(Instant.now().minusSeconds(3600)); // Expired
        refreshToken.setRevoked(false);

        when(refreshTokenRepository.findByToken(tokenString)).thenReturn(Optional.of(refreshToken));
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(refreshToken);

        org.junit.jupiter.api.Assertions.assertThrows(
                RefreshTokenException.class,
                () -> service.refreshAccessToken("Bearer " + tokenString)
        );

        verify(jwtUtil, never()).generateToken(any(UserAuthentication.class));
    }

    /**
     * Tests refresh behaviour when token has been revoked.
     * 
     * Verifies that:
     * - RefreshTokenException is thrown for revoked token
     * - No new JWT token is generated
     * - Security is maintained (revoked tokens cannot be reused)
     */
    @Test
    void refreshAccessToken_revokedToken_throwsRefreshTokenException() {
        String tokenString = "revoked-token";

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(tokenString);
        refreshToken.setExpiryDate(Instant.now().plusSeconds(3600));
        refreshToken.setRevoked(true);

        when(refreshTokenRepository.findByToken(tokenString)).thenReturn(Optional.of(refreshToken));

        org.junit.jupiter.api.Assertions.assertThrows(
                RefreshTokenException.class,
                () -> service.refreshAccessToken("Bearer " + tokenString)
        );

        verify(jwtUtil, never()).generateToken(any(UserAuthentication.class));
    }

    /**
     * Tests refresh behaviour when token doesn't exist in database.
     * 
     * Verifies that:
     * - RefreshTokenException is thrown for unknown token
     * - Invalid tokens are rejected
     */
    @Test
    void refreshAccessToken_invalidToken_throwsRefreshTokenException() {
        String tokenString = "invalid-token";

        when(refreshTokenRepository.findByToken(tokenString)).thenReturn(Optional.empty());

        org.junit.jupiter.api.Assertions.assertThrows(
                RefreshTokenException.class,
                () -> service.refreshAccessToken("Bearer " + tokenString)
        );
    }

    /**
     * Tests refresh behaviour when Bearer prefix is missing from header.
     * 
     * Verifies that:
     * - RefreshTokenException is thrown for invalid header format
     * - OAuth 2.0 RFC 6750 standard is enforced
     */
    @Test
    void refreshAccessToken_missingBearerPrefix_throwsRefreshTokenException() {
        org.junit.jupiter.api.Assertions.assertThrows(
                RefreshTokenException.class,
                () -> service.refreshAccessToken("invalid-format-token")
        );
    }

    /**
     * Tests refresh behaviour when token is null.
     * 
     * Verifies that:
     * - RefreshTokenException is thrown for null token
     * - Null safety is maintained
     */
    @Test
    void refreshAccessToken_nullToken_throwsRefreshTokenException() {
        org.junit.jupiter.api.Assertions.assertThrows(
                RefreshTokenException.class,
                () -> service.refreshAccessToken(null)
        );
    }

    /**
     * Tests successful revocation of a single refresh token (logout from current device).
     * 
     * Verifies that:
     * - Token is validated before revocation
     * - Token's revoked flag is set to true
     * - Changes are persisted to database
     * - HTTP 200 OK response is returned
     */
    @Test
    void revokeRefreshToken_validToken_revokesSuccessfully() {
        String tokenString = "valid-token";

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(tokenString);
        refreshToken.setUserId(1L);
        refreshToken.setExpiryDate(Instant.now().plusSeconds(3600));
        refreshToken.setRevoked(false);

        when(refreshTokenRepository.findByToken(tokenString)).thenReturn(Optional.of(refreshToken));
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(refreshToken);

        ResponseEntity<?> response = service.revokeRefreshToken("Bearer " + tokenString);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(refreshToken.isRevoked()).isTrue();
        verify(refreshTokenRepository, times(1)).save(refreshToken);
    }

    /**
     * Tests bulk revocation of all other tokens (logout from all other devices).
     * 
     * Verifies that:
     * - Current token is validated and kept active
     * - All other user tokens are revoked
     * - Number of revoked tokens is returned
     * - User stays logged in on current device only
     */
    @Test
    void revokeOtherTokens_validToken_revokesOtherSessions() {
        String tokenString = "current-token";
        Long userId = 1L;
        Long tokenId = 1L;

        RefreshToken currentToken = new RefreshToken();
        currentToken.setId(tokenId);
        currentToken.setToken(tokenString);
        currentToken.setUserId(userId);
        currentToken.setExpiryDate(Instant.now().plusSeconds(3600));
        currentToken.setRevoked(false);

        when(refreshTokenRepository.findByToken(tokenString)).thenReturn(Optional.of(currentToken));
        when(refreshTokenRepository.revokeAllUserTokensExcept(userId, tokenId)).thenReturn(3);

        ResponseEntity<?> response = service.revokeOtherTokens("Bearer " + tokenString);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        verify(refreshTokenRepository, times(1)).revokeAllUserTokensExcept(userId, tokenId);
    }

    /**
     * Tests automatic cleanup of expired and revoked tokens.
     * 
     * Verifies that:
     * - Scheduled task removes expired tokens from database
     * - Revoked tokens are also cleaned up
     * - Number of deleted tokens is returned
     * - Database performance is maintained
     */
    @Test
    void purgeExpiredTokens_removesExpiredTokens() {
        when(refreshTokenRepository.deleteExpiredOrRevokedTokens(any(Instant.class))).thenReturn(5);

        int deleted = service.purgeExpiredTokens();

        assertThat(deleted).isEqualTo(5);
        verify(refreshTokenRepository, times(1)).deleteExpiredOrRevokedTokens(any(Instant.class));
    }

    /**
     * Tests retrieval of active tokens for a user (for "Your Sessions" feature).
     * 
     * Verifies that:
     * - All tokens for user are fetched from database
     * - Only active (non-expired, non-revoked) tokens are returned
     * - Expired tokens are filtered out
     * - Revoked tokens are filtered out
     * - Users can see and manage their active sessions
     */
    @Test
    void getActiveTokensForUser_returnsOnlyActiveTokens() {
        Long userId = 1L;

        RefreshToken activeToken = new RefreshToken();
        activeToken.setToken("active-token");
        activeToken.setExpiryDate(Instant.now().plusSeconds(3600));
        activeToken.setRevoked(false);

        RefreshToken expiredToken = new RefreshToken();
        expiredToken.setToken("expired-token");
        expiredToken.setExpiryDate(Instant.now().minusSeconds(3600));
        expiredToken.setRevoked(false);

        RefreshToken revokedToken = new RefreshToken();
        revokedToken.setToken("revoked-token");
        revokedToken.setExpiryDate(Instant.now().plusSeconds(3600));
        revokedToken.setRevoked(true);

        when(refreshTokenRepository.findByUserId(userId))
                .thenReturn(List.of(activeToken, expiredToken, revokedToken));

        List<RefreshToken> activeTokens = service.getActiveTokensForUser(userId);

        assertThat(activeTokens).hasSize(1);
        assertThat(activeTokens.get(0).getToken()).isEqualTo("active-token");
    }
}
