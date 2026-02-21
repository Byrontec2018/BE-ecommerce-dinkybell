package com.dinkybell.ecommerce.authentication.handler;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.dinkybell.ecommerce.shared.dto.APIResponseDTO;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * JwtAuthenticationEntryPoint is the entry point for handling JWT authentication errors.
 * 
 * This component implements Spring Security's {@link AuthenticationEntryPoint} interface
 * and is invoked when an unauthenticated user attempts to access a protected resource.
 * 
 * Functionality:
 * - Intercepts authentication exceptions (missing, expired, or invalid token)
 * - Returns an HTTP 401 (Unauthorised) response in JSON format
 * - Communicates the reason for the authentication failure to the client
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

  private final ObjectMapper objectMapper;

    /**
     * Handles authentication errors and returns a JSON response to the client.
     * 
     * This method is invoked when an authentication exception is thrown during
     * the JWT token validation process. If the token is missing, expired,
     * or invalid, the client receives a 401 response with an error message.
     *
     * @param request  the HTTP request received from the client
     * @param response the HTTP response to send to the client
     * @param ex       the authentication exception containing the error message
     * @throws IOException if an error occurs whilst writing the response
     */
    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException ex) throws IOException {

        log.info("Authentication failed: {}", ex.getMessage());

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        String message = resolveMessage(ex);

        APIResponseDTO<Object> apiResponse = APIResponseDTO.<Object>builder()
          .status(HttpServletResponse.SC_UNAUTHORIZED)
          .message(message)
          .data(null)
          .errors(List.of(message))
          .timestamp(LocalDateTime.now())
          .build();

        objectMapper.writeValue(response.getOutputStream(), apiResponse);
    }

      private String resolveMessage(AuthenticationException ex) {
        if (ex instanceof CredentialsExpiredException) {
          return "JWT token has expired. A new token must be requested.";
        }
        if (ex instanceof BadCredentialsException) {
          return ex.getMessage() != null ? ex.getMessage() : "Invalid JWT token.";
        }
        if (ex instanceof InsufficientAuthenticationException) {
          return "Authentication required.";
        }
        return ex.getMessage() != null ? ex.getMessage() : "Unauthorised";
      }
}