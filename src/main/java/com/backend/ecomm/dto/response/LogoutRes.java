package com.backend.ecomm.dto.response;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class LogoutRes {
    private String success;
    private String message;
}
