package com.dinkybell.ecommerce.repositories;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import com.dinkybell.ecommerce.entities.Authentication;

public interface AuthenticationRepository extends JpaRepository<Authentication, Integer> {

    Optional<Authentication> findByEmail(String email);

    boolean existsByEmail(String email);

}
