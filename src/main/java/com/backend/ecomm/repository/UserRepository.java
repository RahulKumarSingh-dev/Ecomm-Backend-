package com.backend.ecomm.repository;


import com.backend.ecomm.entity.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Repository;

@Repository
public class UserRepository {
    public User findUserByEmail(String email) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        User user = new User(email, encoder.encode("123456"));
        user.setFirstName("FirstName");
        user.setLastName("LastName");
        return user;
    }
}
