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
 * JwtAuthenticationEntryPoint è il punto di ingresso per la gestione degli errori di autenticazione JWT.
 * 
 * Questo componente implementa l'interfaccia {@link AuthenticationEntryPoint} di Spring Security
 * e viene richiamato quando un utente non autenticato tenta di accedere a una risorsa protetta.
 * 
 * Funzionalità:
 * - Intercetta le eccezioni di autenticazione (token mancante, scaduto, invalido)
 * - Restituisce una risposta HTTP 401 (Unauthorized) in formato JSON
 * - Comunica il motivo dell'errore di autenticazione al client
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

  private final ObjectMapper objectMapper;

    /**
     * Gestisce l'errore di autenticazione e restituisce una risposta JSON al client.
     * 
     * Questo metodo viene invocato quando un'eccezione di autenticazione viene lanciata
     * durante il processo di validazione del token JWT. Se il token è assente, scaduto
     * o invalido, il client riceve una risposta 401 con il messaggio di errore.
     *
     * @param request  la richiesta HTTP ricevuta dal client
     * @param response la risposta HTTP da inviare al client
     * @param ex       l'eccezione di autenticazione che contiene il messaggio di errore
     * @throws IOException se si verifica un errore durante la scrittura della risposta
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
          return "Token JWT scaduto. È necessario richiedere un nuovo token.";
        }
        if (ex instanceof BadCredentialsException) {
          return ex.getMessage() != null ? ex.getMessage() : "Token JWT non valido.";
        }
        if (ex instanceof InsufficientAuthenticationException) {
          return "Autenticazione richiesta.";
        }
        return ex.getMessage() != null ? ex.getMessage() : "Unauthorized";
      }
}