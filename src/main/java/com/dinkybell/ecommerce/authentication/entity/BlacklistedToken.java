package com.dinkybell.ecommerce.authentication.entity;

import java.util.Date;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


/**
 * Entity representing a blacklisted (invalidated) JWT token.
 * 
 * This entity stores information about tokens that have been invalidated through logout but have
 * not yet reached their natural expiration time. The database table includes an index on the
 * expiryDate field to optimize cleanup operations.
 */
@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "token_blacklist",
        indexes = {@Index(name = "idx_expiry_date", columnList = "expiryDate")})
public class BlacklistedToken {

    /**
     * The JWT ID (jti) claim value, used as the primary key. This is a unique identifier for each
     * JWT token.
     */
    @Id
    @Column(length = 255)
    private String jti;

    /**
     * The expiration date of the token. Used to automatically clean up expired entries.
     */
    @Column(nullable = false)
    @Temporal(TemporalType.TIMESTAMP)
    private Date expiryDate;
}
