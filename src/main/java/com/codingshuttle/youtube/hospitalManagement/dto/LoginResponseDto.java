package com.codingshuttle.youtube.hospitalManagement.dto;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class LoginResponseDto {
    private String  jwt;
    private Long userId;
    private String refreshToken;
}
