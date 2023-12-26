package com.backend.ecomm.dto.request;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class PasswordResetReq {
    private String password;
    private String confirmPassword;
}
