package com.backend.ecomm.controller;

import com.backend.ecomm.dto.request.LoginReq;
import com.backend.ecomm.entity.User;
import com.backend.ecomm.service.UserService;
import com.backend.ecomm.dto.response.AuthResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class UserController {

    @Autowired
    UserService userService;
    @PostMapping("/register")
    public AuthResponse register(@RequestBody User user){
        return userService.registerUser(user);
    }

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginReq loginReq){
        return userService.loginUser(loginReq);
    }



}
