package com.dinkybell.ecommerce.repositories;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import com.dinkybell.ecommerce.entities.UserAuthentication;

public interface UserAuthenticationRepository extends JpaRepository<UserAuthentication, Integer> {

    Optional<UserAuthentication> findByEmail(String email);

    boolean existsByEmail(String email);

    UserAuthentication findByResetToken(String resetToken);

}
