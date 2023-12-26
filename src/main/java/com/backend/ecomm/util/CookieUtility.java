package com.backend.ecomm.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

@Component
public class CookieUtility {

    public void addTokenInCookie(String accessToken,String refreshToken, HttpServletResponse response){
        Cookie accessTokenCookie = new Cookie("accessToken", accessToken);
        accessTokenCookie.setHttpOnly(true); // Protect against XSS attacks
        accessTokenCookie.setSecure(true);   // Only transmit over HTTPS (recommended)
        accessTokenCookie.setPath("/");      // Make accessible across the entire application
        response.addCookie(accessTokenCookie);

        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
        refreshTokenCookie.setHttpOnly(true); // Protect against XSS attacks
        refreshTokenCookie.setSecure(true);   // Only transmit over HTTPS (recommended)
        refreshTokenCookie.setPath("/");      // Make accessible across the entire application
        response.addCookie(refreshTokenCookie);
    }
}
