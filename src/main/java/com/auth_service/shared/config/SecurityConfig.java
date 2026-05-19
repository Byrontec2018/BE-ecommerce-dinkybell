package com.auth_service.shared.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import java.util.Arrays;
import java.util.Objects;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.lang.NonNull;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.auth_service.authentication.config.JwtAuthFilter;
import com.auth_service.authentication.handler.JwtAuthenticationEntryPoint;


import lombok.RequiredArgsConstructor;

/**
 * Spring Security Configuration.
 * 
 * This class configures the security aspects of the application including:
 * - Modern password encoding strategy (Argon2id)
 * - HTTP security settings 
 * - JWT authentication mechanism
 * - Authorization rules for endpoints
 * 
 * Uses Argon2id exclusively for enhanced security - the winner of 
 * Password Hashing Competition (PHC) 2015 and OWASP recommended algorithm.
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final JwtAuthenticationEntryPoint entryPoint;

    @org.springframework.beans.factory.annotation.Value("${app.cors.allowed-origins:http://localhost:8080}")
    private String allowedOrigins;

    /**
     * Creates the primary password encoder bean using modern Argon2id algorithm.
     * 
     * Argon2id provides superior security compared to BCrypt:
     * - Memory-hard function (resistant to GPU/ASIC attacks)
     * - Configurable time, memory, and parallelism costs
     * - Winner of Password Hashing Competition (PHC) 2015
     * - Recommended by OWASP for password hashing
     * 
     * @return The Argon2PasswordEncoder instance
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new Argon2PasswordEncoder();
    }

    @Configuration
    public class CorsConfig implements WebMvcConfigurer {
        @Override
        public void addCorsMappings(@NonNull CorsRegistry registry) {
            String[] origins = Arrays.stream(allowedOrigins.split(","))
                    .map(String::trim)
                    .filter(origin -> !origin.isEmpty())
                    .toArray(String[]::new);
            registry.addMapping("/api/**")
                .allowedOrigins(Objects.requireNonNull(origins))
                    .allowedMethods("GET", "POST", "PUT", "DELETE")
                    .allowedHeaders("*")
                    .allowCredentials(true);
        }
    }

    /**
     * Configures HTTP security settings for the application.
     * 
     * Implements JWT-based security with specific endpoint permissions.
     * Public endpoints are allowed without authentication while protected
     * endpoints require proper authentication and authorization.
     * 
     * @param http The HttpSecurity to configure
     * @return The built SecurityFilterChain
     * @throws Exception If configuration fails
     */
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        return http

            // Disable CSRF as we're using stateless JWT authentication
            .csrf(AbstractHttpConfigurer::disable)

            // Configure session management to be stateless
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            // Disable form login and HTTP Basic            
            .formLogin(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            
            // Configure authorization rules
            .authorizeHttpRequests(auth -> auth
                // Public endpoints (centralized in SecurityConstants to maintain consistency with JwtAuthFilter)
                .requestMatchers(SecurityConstants.PUBLIC_PATHS).permitAll()
                // Protected endpoints
                .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )           

            // Use custom entry point for authentication failures
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(entryPoint)
            )
            
            // Add JWT filter before the standard authentication filter
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)            
            .build();

    }

}
