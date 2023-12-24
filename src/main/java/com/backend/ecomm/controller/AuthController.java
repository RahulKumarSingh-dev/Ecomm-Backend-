package com.backend.ecomm.controller;


import com.backend.ecomm.dto.response.AuthResponse;
import com.backend.ecomm.service.UserService;
import com.backend.ecomm.util.JwtUtil;
import com.backend.ecomm.entity.User;
import com.backend.ecomm.dto.request.LoginReq;
import com.backend.ecomm.dto.response.ErrorRes;
import com.backend.ecomm.dto.response.LoginRes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/api/v1/auth")
public class AuthController {

    @Autowired
    UserService userService;

    @PostMapping("/register")
    public AuthResponse register(@RequestBody User user) {
        return userService.registerUser(user);
    }

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginReq loginReq) {
        return userService.loginUser(loginReq);
    }


}