package com.backend.ecomm.controller;

import com.backend.ecomm.dto.response.LogoutRes;
import com.backend.ecomm.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1")
public class UserController {
    @Autowired
    UserService userService;
    @GetMapping("/logout")
    public ResponseEntity logout(HttpServletRequest request,HttpServletResponse response){
        return userService.logoutUser(request,response);
    }

    @GetMapping("refresh-token")
    public ResponseEntity refreshToken(HttpServletRequest request,HttpServletResponse response){

        return userService.refreshToken(request,response);
    }


    /*


     */




}
