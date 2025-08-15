package com.dinkybell.ecommerce.enums;

/**
 * Enum representing user roles in the system.
 * 
 * Roles define the permission levels and access rights of users. This enum is used for role-based
 * access control throughout the application.
 */
public enum Role {
    /**
     * Standard user with limited access to system features. Can access user-specific functionality
     * like placing orders.
     */
    USER,

    /**
     * Administrator with full access to system features. Can manage users, products, orders, and
     * system settings.
     */
    ADMIN
}
