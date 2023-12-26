package com.backend.ecomm.controller;


import com.backend.ecomm.dto.request.ForgotPassswordReq;
import com.backend.ecomm.dto.request.PasswordResetReq;
import com.backend.ecomm.dto.response.AuthResponse;
import com.backend.ecomm.service.UserService;
import com.backend.ecomm.util.JwtUtil;
import com.backend.ecomm.entity.User;
import com.backend.ecomm.dto.request.LoginReq;
import com.backend.ecomm.dto.response.ErrorRes;
import com.backend.ecomm.dto.response.LoginRes;
import jakarta.annotation.Nonnull;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
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

    // TODO: change the token -> accessToken and refreshToken
    @PostMapping("/register")
    public AuthResponse register(@RequestBody User user, HttpServletResponse response) {
        return userService.registerUser(user,response);
    }

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginReq loginReq,HttpServletResponse response) {

        return userService.loginUser(loginReq,response);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity forgotPassword(@RequestBody @Nonnull ForgotPassswordReq forgotPassswordReq){
        return userService.fogotPassword(forgotPassswordReq.getEmail());
    }

    @PostMapping("/password/reset/{token}")
    public ResponseEntity resetPassword(@PathVariable String token, @RequestBody PasswordResetReq passwordResetReq){

        return userService.resetPassword(token,passwordResetReq);
    }

    @DeleteMapping("/user/delete/{id}")
    public ResponseEntity deleteUser(@PathVariable int id){
        return userService.deleteUser(id);
    }

}