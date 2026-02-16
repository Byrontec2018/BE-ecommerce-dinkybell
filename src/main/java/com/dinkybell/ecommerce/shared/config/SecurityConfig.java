package com.dinkybell.ecommerce.shared.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.lang.NonNull;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.dinkybell.ecommerce.authentication.config.JwtAuthFilter;
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
            registry.addMapping("/api/**")
                    .allowedOrigins("http://192.168.1.176:8080/api/v1/auth/*")
                    .allowedOrigins("http://localhost:8080/api/v1/auth/*")
                    .allowedOrigins("http://192.168.1.176:8080/swagger-ui/**")
                    .allowedOrigins("http://localhost:8080/swagger-ui/**")
                    .allowedOrigins("http://192.168.1.176:8080//v3/api-docs/**")
                    .allowedOrigins("http://localhost:8080/v3/api-docs/**")
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
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF as we're using stateless JWT authentication
            .csrf(AbstractHttpConfigurer::disable)
            
            // Configure authorization rules
            .authorizeHttpRequests(auth -> auth
                // Public endpoints
                .requestMatchers("/api/v1/auth/**").permitAll()
                .requestMatchers("/api/v1/public/**").permitAll()
                .requestMatchers("/actuator/health").permitAll()
                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
                .requestMatchers("/users/public").permitAll() // Allow public access to user profiles TEST
                // Protected endpoints
                .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            
            // Configure session management to be stateless
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            
            // Disable form login and HTTP Basic
            .httpBasic(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            
            // Add JWT filter before the standard authentication filter
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
            
        return http.build();
    }
}
