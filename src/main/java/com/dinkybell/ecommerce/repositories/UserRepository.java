package com.dinkybell.ecommerce.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.dinkybell.ecommerce.entities.User;

/**
 * Repository interface for accessing and managing User entities.
 * 
 * This repository provides standard database CRUD operations for user profiles. It's marked
 * with @Repository for Spring component scanning and exception translation.
 * 
 * This repository is separate from UserAuthenticationRepository to allow for separation of concerns
 * between user profile data and authentication data.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Integer> {

}
