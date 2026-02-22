package com.dinkybell.ecommerce.authentication.service;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.dinkybell.ecommerce.authentication.dto.JwtResponseDTO;
import com.dinkybell.ecommerce.shared.util.SecureTokenGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import com.dinkybell.ecommerce.authentication.entity.RefreshToken;
import com.dinkybell.ecommerce.authentication.entity.UserAuthentication;
import com.dinkybell.ecommerce.authentication.exception.RefreshTokenException;
import com.dinkybell.ecommerce.authentication.repository.RefreshTokenRepository;
import com.dinkybell.ecommerce.authentication.repository.UserAuthenticationRepository;
import com.dinkybell.ecommerce.authentication.util.JwtUtil;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Service that handles refresh token operations.
 * 
 * This service manages the lifecycle of refresh tokens including:
 * - Creation of new tokens during login
 * - Validation and use of tokens to generate new JWTs
 * - Revocation of tokens during logout
 * - Cleanup of expired tokens
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {
    
    @Value("${jwt.refresh-token.expiration}")
    private Long refreshTokenDurationMs;
    
    @Value("${jwt.refresh-token.max-per-user:5}")
    private Integer maxTokensPerUser;
    
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserAuthenticationRepository userAuthenticationRepository;
    private final JwtUtil jwtUtil;
    
    /**
     * Creates a new refresh token for a user during login, or returns existing valid token for same device.
     * 
     * This method:
     * 1. Checks if a valid token already exists for this device
     * 2. If exists and valid, returns the existing token (avoiding duplicates)
     * 3. If not exists or expired, creates a new token
     * 4. Records device information for security tracking
     * 5. Enforces maximum tokens per user limit
     * 
     * @param userId The ID of the user
     * @param request The HTTP request (for device info)
     * @return The refresh token (existing or newly created)
     */
    @Transactional
    public RefreshToken createRefreshToken(Long userId, HttpServletRequest request) {
        // Check if user exists
        if (userId == null) {
            throw new IllegalArgumentException("User ID cannot be null");
        }

        userAuthenticationRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + userId));
        
        // Get device information
        String deviceInfo = extractDeviceInfo(request);
        
        // Check if a valid token already exists for this device
        Optional<RefreshToken> existingToken = refreshTokenRepository
                .findActiveTokenByUserIdAndDevice(userId, deviceInfo, Instant.now());
        
        if (existingToken.isPresent()) {
            RefreshToken token = existingToken.get();
            // Update last used timestamp to extend sliding window
            token.setLastUsedAt(Instant.now());
            RefreshToken updatedToken = refreshTokenRepository.save(token);
            log.debug("Reusing existing valid refresh token for user {} on same device", userId);
            return updatedToken;
        }
        
        // Enforce token limit per user if configured
        if (maxTokensPerUser > 0) {
            long activeTokenCount = refreshTokenRepository.countActiveTokensByUserId(userId, Instant.now());
            if (activeTokenCount >= maxTokensPerUser) {
                // If limit reached, revoke the oldest token
                refreshTokenRepository.findOldestActiveTokenByUserId(userId, Instant.now())
                    .ifPresent(oldestToken -> {
                        oldestToken.setRevoked(true);
                        refreshTokenRepository.save(oldestToken);
                        log.debug("Revoked oldest token for user {} due to limit", userId);
                    }
                );
            }
        }
        
        // Create and save new refresh token
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUserId(userId);
        refreshToken.setToken(SecureTokenGenerator.generateLongToken()); // 256-bit cryptographically secure token for 30-day validity
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        refreshToken.setDeviceInfo(deviceInfo);
        refreshToken.setCreatedAt(Instant.now());
        
        RefreshToken savedToken = refreshTokenRepository.save(refreshToken);
        log.debug("Created new refresh token for user {} on new device", userId);
        
        return savedToken;
    }
    
    /**
     * Validates a refresh token and generates a new JWT access token.
     * 
     * This method:
     * 1. Verifies the token exists
     * 2. Checks that it's not expired or revoked
     * 3. Updates the last used timestamp (sliding window)
     * 4. Generates a new JWT access token
     * 
     * @param token The refresh token string
     * @return A new JWT access token
     * @throws RefreshTokenException if the token is invalid, expired, or revoked
     */
    
    /**
     * Validates a refresh token and generates a new JWT access token.
     * Returns standardized APIResponseDTO with JWT details.
     * 
     * This method:
     * 1. Verifies the token exists and is valid
     * 2. Updates the last used timestamp (sliding window)
     * 3. Generates a new JWT access token
     * 4. Returns response following APIResponseDTO pattern
     * 
     * @param token The refresh token string (already extracted from Bearer header)
     * @return ResponseEntity with APIResponseDTO containing JWT data
     * @throws RefreshTokenException if the token is invalid, expired, or revoked
     */
    @Transactional
    public ResponseEntity<?> refreshAccessToken(String token) {

        log.debug("Processing token refresh request");

        // Extract token from Bearer header format
        token = extractTokenFromBearerHeader(token);

        // Verify the refresh token
        RefreshToken refreshToken = verifyRefreshToken(token);

        log.debug("Refresh token verified for user {}", refreshToken.getUserId());
        
        // Update last used timestamp (sliding window expiry)
        refreshToken.setLastUsedAt(Instant.now());
        refreshTokenRepository.save(refreshToken);
        
        // Find the associated user authentication
        Long userId = refreshToken.getUserId();
        if (userId == null) {
            throw new RefreshTokenException("User ID is null for this token");
        }
        UserAuthentication userAuth = userAuthenticationRepository.findById(userId)
                .orElseThrow(() -> new RefreshTokenException("User authentication not found for this token"));
        
        // Generate new JWT access token
        String newAccessToken = jwtUtil.generateToken(userAuth);
        log.debug("Generated new access token for user {}", refreshToken.getUserId());
        
        // Get token expiration date
        java.util.Date tokenExpirationTime = jwtUtil.extractExpirationDate(newAccessToken);
        
        // Build JWT response data
        JwtResponseDTO jwtData = new JwtResponseDTO(
                newAccessToken, 
                token,
                userAuth.getEmail(),
                tokenExpirationTime);
        
        // Return standardized API response
        return ApiResponseFactory.buildResponse(
                HttpStatus.OK,
                "Access token refreshed successfully",
                jwtData,
                null);
    }
    
    /**
     * Revokes a single refresh token.
     * 
     * @param token The token to revoke
     * @throws RefreshTokenException if the token is invalid
     */
    @Transactional
    public ResponseEntity<?> revokeRefreshToken(String token) {

        log.info("Attempting to revoke refresh token: {}", token);

        // Extract token from Bearer header format
        token = extractTokenFromBearerHeader(token);

        // Verify the refresh token
        RefreshToken refreshToken = verifyRefreshToken(token);

        log.debug("Revoking refresh token for user {}", refreshToken.getUserId());

        // Mark the token as revoked
        refreshToken.setRevoked(true);
        refreshTokenRepository.save(refreshToken);

        // Return a generic confirmation response
        return ApiResponseFactory.buildResponse(
                HttpStatus.OK,
                "Refresh token revoked successfully",
                "Token revoked:" + token,
                null);
    }
    
    /**
     * Revokes all refresh tokens for a user except the current one.
     * This is used for the "log out from all other devices" functionality.
     * 
     * @param token The current token to keep active
     * @throws RefreshTokenException if the token is invalid
     */
    @Transactional
    public ResponseEntity<?> revokeOtherTokens(String token) {

        log.info("Attempting to revoke other sessions for token: {}", token);

        // Extract token from Bearer header format
        token = extractTokenFromBearerHeader(token);

        // Verify the refresh token
        RefreshToken refreshToken = verifyRefreshToken(token);

        log.info("Revoking other tokens for user {}", refreshToken.getUserId());
        log.info("Current token ID: {}", refreshToken.getId());

        // Revoke all other tokens for the user except the current one
        int revokedCount = refreshTokenRepository.revokeAllUserTokensExcept(
                refreshToken.getUserId(), refreshToken.getId());

        log.info("Revoked {} other tokens for user {}", revokedCount, refreshToken.getUserId());

        return ApiResponseFactory.buildResponse(
                HttpStatus.OK,
                "Other sessions revoked successfully",
                "Revoked " + revokedCount + " other tokens",
                null);
    }
    
    /**
     * Removes all expired and revoked tokens from the database.
     * This should be called by a scheduled task periodically.
     * 
     * @return The number of tokens removed
     */
    @Transactional
    public int purgeExpiredTokens() {
        int deleted = refreshTokenRepository.deleteExpiredOrRevokedTokens(Instant.now());
        log.debug("Purged {} expired or revoked refresh tokens", deleted);
        return deleted;
    }
    
    /**
     * Gets all active refresh tokens for a user.
     * This is useful for the "Your Sessions" feature in account settings.
     * 
     * @param userId The user ID
     * @return A list of active refresh tokens
     */
    public List<RefreshToken> getActiveTokensForUser(Long userId) {
        List<RefreshToken> tokens = refreshTokenRepository.findByUserId(userId);
        Instant now = Instant.now();
        return tokens.stream()
                .filter(token -> !token.isRevoked() && token.getExpiryDate().isAfter(now))
                .toList();
    }
    
    /**
     * Helper method to verify and retrieve a refresh token.
     * 
     * @param token The token string
     * @return The RefreshToken entity
     * @throws RefreshTokenException if the token is invalid, expired, or revoked
     */
    private RefreshToken verifyRefreshToken(String token) {

        if (token == null) {
            throw new RefreshTokenException("Refresh token is required");
        }
        
        return refreshTokenRepository.findByToken(token)
                .map(refreshToken -> {
                    // Check if revoked
                    if (refreshToken.isRevoked()) {
                        throw new RefreshTokenException("Refresh token was revoked");
                    }
                    
                    // Check if expired
                    if (refreshToken.getExpiryDate().isBefore(Instant.now())) {
                        refreshToken.setRevoked(true);
                        refreshTokenRepository.save(refreshToken);
                        throw new RefreshTokenException("Refresh token has expired");
                    }
                    
                    return refreshToken;
                })
                .orElseThrow(() -> new RefreshTokenException("Invalid refresh token"));
    }
    
    /**
     * Extracts comprehensive device information from HTTP request to create a unique device fingerprint.
     * 
     * This method creates a stable identifier for the same device/browser combination while
     * being reasonably resistant to minor changes (like IP changes due to WiFi switching).
     * The fingerprint includes multiple factors to distinguish between genuine different devices.
     * 
     * @param request The HTTP request containing device information
     * @return A string containing device fingerprint for token deduplication
     */
    private String extractDeviceInfo(HttpServletRequest request) {
        StringBuilder fingerprint = new StringBuilder();
        
        // 1. User-Agent (most stable identifier for same browser/app)
        String userAgent = request.getHeader("User-Agent");
        if (userAgent != null && !userAgent.trim().isEmpty()) {
            // Use hash to keep fingerprint manageable but stable
            fingerprint.append("UA:").append(Math.abs(userAgent.hashCode())).append(";");
        } else {
            fingerprint.append("UA:unknown;");
        }
        
        // 2. Accept-Language (helps distinguish users sharing same computer)
        String acceptLang = request.getHeader("Accept-Language");
        if (acceptLang != null && !acceptLang.trim().isEmpty()) {
            fingerprint.append("LANG:").append(Math.abs(acceptLang.hashCode())).append(";");
        } else {
            fingerprint.append("LANG:unknown;");
        }
        
        // 3. Accept header (browser/app specific)
        String accept = request.getHeader("Accept");
        if (accept != null && !accept.trim().isEmpty()) {
            fingerprint.append("ACCEPT:").append(Math.abs(accept.substring(0, Math.min(50, accept.length())).hashCode())).append(";");
        } else {
            fingerprint.append("ACCEPT:unknown;");
        }
        
        // 4. IP Address (less stable but useful for geolocation context)
        // NOTE: IP changes are common (WiFi switching, mobile data, VPN)
        // so we use it but don't rely on it entirely for device identification
        String ipAddress = extractClientIp(request);
        if (ipAddress != null && !ipAddress.trim().isEmpty()) {
            fingerprint.append("IP:").append(ipAddress).append(";");
        } else {
            fingerprint.append("IP:unknown;");
        }
        
        // 5. Additional securit
        String secFetchSite = request.getHeader("Sec-Fetch-Site");
        if (secFetchSite != null && !secFetchSite.trim().isEmpty()) {
            fingerprint.append("SEC:").append(secFetchSite).append(";");
        }
        
        String deviceFingerprint = fingerprint.toString();
        log.debug("Generated device fingerprint: {}", deviceFingerprint);
        
        return deviceFingerprint;
    }
    
    /**
     * Extracts the client's real IP address from an HTTP request.
     * Handles proxies, load balancers, CDNs and VPNs by checking standard headers.
     * 
     * @param request The HTTP request
     * @return The client's IP address or "unknown" if cannot be determined
     */
    private String extractClientIp(HttpServletRequest request) {
        // Headers to check in order of priority
        String[] headersToCheck = {
            "CF-Connecting-IP",      // Cloudflare
            "X-Real-IP",             // Nginx proxy
            "X-Forwarded-For",       // Standard proxy header
            "X-Forwarded",           // Alternative proxy header
            "Forwarded",             // RFC 7239 standard
            "HTTP_X_FORWARDED_FOR",  // Apache variant
            "Proxy-Client-IP",       // Apache mod_proxy
            "WL-Proxy-Client-IP",    // WebLogic
            "HTTP_CLIENT_IP",        // General purpose
            "HTTP_X_CLUSTER_CLIENT_IP", // Cluster setups
            "X-Cluster-Client-IP"    // Additional cluster variant
        };
        
        for (String header : headersToCheck) {
            String ipFromHeader = request.getHeader(header);
            
            if (ipFromHeader != null && !ipFromHeader.trim().isEmpty() && 
                !"unknown".equalsIgnoreCase(ipFromHeader.trim()) &&
                !"null".equalsIgnoreCase(ipFromHeader.trim())) {
                
                // Handle comma-separated IPs (X-Forwarded-For can contain multiple IPs)
                String[] ips = ipFromHeader.split(",");
                for (String ip : ips) {
                    String cleanIp = ip.trim();
                    
                    // Skip private/local IPs to get the real external IP
                    if (isValidPublicIp(cleanIp)) {
                        return cleanIp;
                    }
                }
                
                // If no public IP found, return the first non-empty IP
                if (ips.length > 0 && !ips[0].trim().isEmpty()) {
                    return ips[0].trim();
                }
            }
        }
        
        // Fallback to request remote address
        String remoteAddr = request.getRemoteAddr();
        return (remoteAddr != null && !remoteAddr.trim().isEmpty()) ? remoteAddr : "unknown";
    }
    
    /**
     * Checks if an IP address is a valid public IP (not private/local/invalid).
     * 
     * @param ip The IP address to check
     * @return true if it's a valid public IP, false otherwise
     */
    private boolean isValidPublicIp(String ip) {
        if (ip == null || ip.trim().isEmpty()) {
            return false;
        }
        
        // Simple validation for common invalid/private IP patterns
        return !ip.startsWith("127.") &&      // Loopback
               !ip.startsWith("10.") &&        // Private Class A
               !ip.startsWith("192.168.") &&   // Private Class C
               !ip.startsWith("172.") &&       // Private Class B (partial check)
               !ip.startsWith("0.") &&         // Invalid
               !ip.startsWith("169.254.") &&   // Link-local
               !ip.equals("::1") &&            // IPv6 loopback
               !ip.startsWith("fc") &&         // IPv6 private
               !ip.startsWith("fd") &&         // IPv6 private
               ip.matches("^[0-9.]+$|^[0-9a-fA-F:]+$"); // Basic IPv4/IPv6 format check
    }

    /**
     * Extracts the token value from RFC 6750 Bearer token format.
     * Expected format: "Bearer <token>"
     * 
     * @param bearerToken The Authorization header value
     * @return The extracted token without "Bearer " prefix
     * @throws RefreshTokenException if header is missing or invalid format
     */
    private String extractTokenFromBearerHeader(String bearerToken) {
        if (bearerToken == null || bearerToken.isBlank()) {
            throw new RefreshTokenException("Authorization header is missing");
        }
        
        if (!bearerToken.startsWith("Bearer ")) {
            throw new RefreshTokenException("Invalid Authorization header format. Expected: Bearer <token>");
        }
        
        String token = bearerToken.substring(7).trim();
        if (token.isEmpty()) {
            throw new RefreshTokenException("Refresh token cannot be empty");
        }
        
        return token;
    }

}
