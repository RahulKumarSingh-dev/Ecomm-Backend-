package com.backend.ecomm.repository;

import com.backend.ecomm.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {
    User findById(int id);
    User findByEmail(String email);

    User findByForgotPasswordToken(String token);

}
