package com.dinkybell.ecommerce.configurations;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security Configuration.
 * 
 * This class configures the security aspects of the application including: - Password encoding
 * strategy (BCrypt) - HTTP security settings - Authentication mechanisms
 * 
 * Currently configured for development with all requests permitted. For production, this should be
 * updated with proper security rules.
 */
@Configuration
public class SecurityConfig {

    /**
     * Creates a password encoder bean for secure password storage.
     * 
     * BCrypt is used as it implements adaptive hashing and includes salt automatically, making it
     * resistant to rainbow table attacks.
     * 
     * @return A BCryptPasswordEncoder instance
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Configures HTTP security settings for the application.
     * 
     * Currently permits all requests for development purposes. Disables CSRF protection, HTTP
     * Basic, and form login as we're using JWT.
     * 
     * @param http The HttpSecurity to configure
     * @return The built SecurityFilterChain
     * @throws Exception If configuration fails
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .csrf(csrf -> csrf.disable()).httpBasic(httpBasic -> httpBasic.disable())
                .formLogin(form -> form.disable()); // Disable form login
        return http.build();
    }

}
