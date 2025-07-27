package com.dinkybell.ecommerce.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.dinkybell.ecommerce.entities.User;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {

}
