package com.backend.ecomm.service;

import com.backend.ecomm.dto.request.LoginReq;
import com.backend.ecomm.dto.response.ErrorRes;
import com.backend.ecomm.dto.response.LoginRes;
import com.backend.ecomm.entity.Role;
import com.backend.ecomm.entity.User;
import com.backend.ecomm.repository.RoleRepository;
import com.backend.ecomm.repository.UserRepository;
import com.backend.ecomm.util.JwtUtil;
import com.backend.ecomm.dto.response.AuthResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class UserService {
    @Autowired
    RoleRepository roleRepository;
    @Autowired
    UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private AuthenticationManager authenticationManager;

    public AuthResponse registerUser(User data) {
        Role role = roleRepository.findById("User").get();
        Set<Role> userRoles = new HashSet<>();
        userRoles.add(role);
        data.setRole(userRoles);
        data.setPassword(getEncodedPassword(data.getPassword()));

        final User user = userRepository.save(data);
        String token = jwtUtil.createToken(user);
        user.setPassword(null);
        return new AuthResponse(user, token);
    }

    public ResponseEntity loginUser(LoginReq loginReq) {
        try {
            Authentication authentication =
                    authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginReq.getEmail(), loginReq.getPassword()));
            String email = authentication.getName();
            User user = userRepository.findByEmail(email);
            String token = jwtUtil.createToken(user);
            AuthResponse authResponse = new AuthResponse(user, token);

            return ResponseEntity.ok(authResponse);

        } catch (BadCredentialsException e) {
            ErrorRes errorResponse = new ErrorRes(HttpStatus.BAD_REQUEST, "Invalid username or password");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        } catch (Exception e) {
            ErrorRes errorResponse = new ErrorRes(HttpStatus.BAD_REQUEST, e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }
    }


    public String getEncodedPassword(String password) {
        return passwordEncoder.encode(password);
    }

}
