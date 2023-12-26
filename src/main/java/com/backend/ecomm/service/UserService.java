package com.backend.ecomm.service;

import com.backend.ecomm.dto.request.LoginReq;
import com.backend.ecomm.dto.request.PasswordResetReq;
import com.backend.ecomm.dto.response.ErrorRes;
import com.backend.ecomm.dto.response.LogoutRes;
import com.backend.ecomm.entity.Role;
import com.backend.ecomm.entity.User;
import com.backend.ecomm.repository.RoleRepository;
import com.backend.ecomm.repository.UserRepository;
import com.backend.ecomm.util.CookieUtility;
import com.backend.ecomm.util.EmailUtility;
import com.backend.ecomm.util.JwtUtil;
import com.backend.ecomm.dto.response.AuthResponse;
import com.backend.ecomm.util.TokenGenerator;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.util.*;

@Service
public class UserService {

    @Value("${JWT_SECRET_KEY}")
    private String secret_key;

    @Value("${ACCESS_TOKEN_VALIDITY}")
    private int accessTokenValidity;

    @Value("${REFRESH_TOKEN_VALIDITY}")
    private int refreshTokenValidity;

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

    @Autowired
    CookieUtility cookieUtility;

    @Autowired
    TokenGenerator tokenGenerator;

    @Autowired
    EmailUtility emailUtility;

    public AuthResponse registerUser(User data, HttpServletResponse response) {
        Role role = roleRepository.findById("User").get();
        Set<Role> userRoles = new HashSet<>();
        userRoles.add(role);
        data.setRole(userRoles);
        data.setPassword(getEncodedPassword(data.getPassword()));

        final User user = userRepository.save(data);
        String accessToken = jwtUtil.createToken(user, accessTokenValidity);
        String refreshToken = jwtUtil.createToken(user, refreshTokenValidity);

        cookieUtility.addTokenInCookie(accessToken, refreshToken, response);
        user.setRefreshToken(refreshToken);
        userRepository.save(user);

        user.setPassword(null);

        return new AuthResponse(user, accessToken);
    }

    public ResponseEntity loginUser(LoginReq loginReq, HttpServletResponse response) {
        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginReq.getEmail(), loginReq.getPassword()));
            String email = authentication.getName();
            User user = userRepository.findByEmail(email);
            String accessToken = jwtUtil.createToken(user, accessTokenValidity);
            String refreshToken = jwtUtil.createToken(user, refreshTokenValidity);
            AuthResponse authResponse = new AuthResponse(user, accessToken);
            cookieUtility.addTokenInCookie(accessToken, refreshToken, response);

            user.setRefreshToken(refreshToken);
            userRepository.save(user);

            return ResponseEntity.ok(authResponse);

        } catch (BadCredentialsException e) {
            ErrorRes errorResponse = new ErrorRes(HttpStatus.BAD_REQUEST, "Invalid username or password");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        } catch (Exception e) {
            ErrorRes errorResponse = new ErrorRes(HttpStatus.BAD_REQUEST, e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }
    }

    // TODO : change tokens -> accessToken, refreshToken
    public ResponseEntity logoutUser(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("token")) {
                    Cookie expiredCookie = new Cookie("token", null);
                    expiredCookie.setMaxAge(0); // Expire immediately
                    expiredCookie.setHttpOnly(true);
                    expiredCookie.setPath("/");
                    expiredCookie.setSecure(true);// Set path to match original
                    response.addCookie(expiredCookie);
                    System.out.println("removing cookie--------------");
                    return ResponseEntity.ok(new LogoutRes("true", "User Logout Successfully"));
                }
            }
        }
        return ResponseEntity.ok(new LogoutRes("false", "Token not found"));

    }

    public ResponseEntity fogotPassword(String email) {
        User user = userRepository.findByEmail(email);
        if (user == null) {
            return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
        }
        /*
        1. create a forgotToken
        2. hashed that forgotToken
        3. create expiry time
        4. save the hashed forgotToken and expiry time in db
        5. craft a url using forgotToken.
        6. mailed that forgotToken to given email.
         */

        // creating a forgotToken

        String forgotToken = tokenGenerator.createToken();

        // hash the forgotToken

        String hashedToken = tokenGenerator.hashToken(forgotToken);

        // create the expiry

        Date expiryTime = tokenGenerator.getExpiryTime(20);

        // 4. save the hashed forgotToken and expiry time in db

        user.setForgotPasswordToken(hashedToken);
        user.setForgotPasswordExpiry(expiryTime);

        userRepository.save(user);

        String urlToMail = ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/v1/auth/password/reset/").path(forgotToken).toUriString();

        String subject = "URL for forgot password";
        Map<String, String> response = new HashMap<>();
        try {
            emailUtility.sendEmail(email, subject, "Copy paste this link in your URL and hit enter \n\n" + urlToMail);

            response.put("message", "Email Sent successfully");

            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            response.put("message", "Something went wrong. Faild to send email");
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }


    }

    public ResponseEntity resetPassword(String token, PasswordResetReq passwordResetReq) {

        String hashedToken = tokenGenerator.hashToken(token);
        User user = userRepository.findByForgotPasswordToken(hashedToken);
        Map<String, String> response = new HashMap<>();
        if (user == null) {
            response.put("message", "Invalid token");
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        }

        Date forgotPasswordExpiry = user.getForgotPasswordExpiry();
        Date currentDate = new Date();

        if (forgotPasswordExpiry.before(currentDate)) {
            response.put("message", "Token in expired");
            return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
        }
        String password = passwordResetReq.getPassword();
        String confirmPassword = passwordResetReq.getConfirmPassword();
        if (!password.equals(confirmPassword)) {
            response.put("message", "Password and confirm password does not match");
            response.put("password", password);
            response.put("confirmPassword", confirmPassword);
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }

        user.setPassword(password);

        userRepository.save(user);

        response.put("message", "Password updated successfully");
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    public ResponseEntity refreshToken(HttpServletRequest request, HttpServletResponse response) {

        /*
        1. get the refresh token from the cookie
        2. find the user from the refresh token
        3. generate new access and refresh token
        4. save new refresh token
        5. send tokens to cookie
         */
        Cookie[] cookies = request.getCookies();
        Map<String, String> res = new HashMap<>();
        if (cookies == null) {
            res.put("message", "Token not found");
            return new ResponseEntity<>(res, HttpStatus.UNAUTHORIZED);
        }
        String incomingRefreshToken = null;

        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("refreshToken")) {
                incomingRefreshToken = cookie.getValue();
            }
        }
        if (incomingRefreshToken == null) {
            res.put("message", "Token not found");
            return new ResponseEntity<>(res, HttpStatus.UNAUTHORIZED);
        }
        String email = null;
        try {
            email = jwtUtil.parseJwtClaims(incomingRefreshToken).getSubject();
        } catch (Exception e) {
            res.put("message", "Refresh Token is expired");
            return new ResponseEntity<>(res, HttpStatus.UNAUTHORIZED);
        }

        User user = userRepository.findByEmail(email);

        if (user == null) {
            res.put("message", "User not found.");
            return new ResponseEntity<>(res, HttpStatus.UNAUTHORIZED);
        }

        String storedRefreshToken = user.getRefreshToken();

        if (!storedRefreshToken.equals(incomingRefreshToken)) {
            res.put("message", "Invalid Refresh Token.");
            return new ResponseEntity<>(res, HttpStatus.UNAUTHORIZED);
        }

        String newAccessToken = jwtUtil.createToken(user, accessTokenValidity);
        String newRefreshToken = jwtUtil.createToken(user, refreshTokenValidity);

        cookieUtility.addTokenInCookie(newAccessToken, newRefreshToken, response);

        user.setRefreshToken(newRefreshToken);
        userRepository.save(user);

        res.put("message", "All tokens refreshed");
        res.put("refreshToken", newRefreshToken);
        res.put("accessToken", newAccessToken);
        return new ResponseEntity<>(res, HttpStatus.OK);

    }

    public String getEncodedPassword(String password) {
        return passwordEncoder.encode(password);
    }

    /*
     TODO : Delete the corresponding row in user_role table.
     This table is auto created with user_id and role_id
     Integrity Constrained
     */

    public ResponseEntity deleteUser(int id){
        Map<String,Object>res=new HashMap<>();
        User user = userRepository.findById(id);
        if(user==null){
            res.put("message","User not found");
            return new ResponseEntity<>(res,HttpStatus.NOT_FOUND);
        }

        userRepository.deleteById(id);
        res.put("message","User deleted successfully");
        res.put("user",user);
        return new ResponseEntity<>(res,HttpStatus.NOT_FOUND);

    }


}
