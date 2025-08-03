package com.dinkybell.ecommerce.entities;

import java.time.LocalDateTime;
import com.dinkybell.ecommerce.enums.Role;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Data
@Entity
@Table(name = "authentications", uniqueConstraints = {@UniqueConstraint(columnNames = {"email"})})
// @UniqueConstraint(columnNames = {"username"})})

public class Authentication {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "user_id", referencedColumnName = "id", nullable = false)
    private User user;

    @Column(length = 20, nullable = true, unique = true)
    @Size(min = 3, max = 20)
    @Pattern(regexp = "^[a-zA-Z0-9_]+$")
    private String username;

    @Column(length = 255, nullable = false, unique = true)
    @Email
    @Size(max = 255)
    private String email;

    @Column(length = 255, nullable = false)
    private String password; // Hashed with BCrypt

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Role role = Role.USER;

    @Column(nullable = false)
    private boolean enabled = false; // Account activation via email

    @Column(name = "email_confirmed_at")
    private LocalDateTime emailConfirmedAt;

    @Column(name = "registration_date", nullable = false, updatable = false)
    private LocalDateTime registrationDate;

    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    @Column(name = "reset_token")
    private String resetToken;

    @Column(name = "reset_token_expiry")
    private LocalDateTime resetTokenExpiry;

    @PrePersist
    protected void onCreate() {
        this.registrationDate = LocalDateTime.now();
    }

    // Getters, setters, equals, hashCode...

}
