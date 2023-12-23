package com.backend.ecomm.dto.response;
import com.backend.ecomm.entity.User;
import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class AuthResponse {

    private User user;
    private String token;
}
