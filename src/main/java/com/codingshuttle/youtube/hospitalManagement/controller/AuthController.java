package com.codingshuttle.youtube.hospitalManagement.controller;

import com.codingshuttle.youtube.hospitalManagement.dto.LoginRequestDto;
import com.codingshuttle.youtube.hospitalManagement.dto.LoginResponseDto;
import com.codingshuttle.youtube.hospitalManagement.dto.RefreshTokenRequestDto;
import com.codingshuttle.youtube.hospitalManagement.dto.SignupRequestDto;
import com.codingshuttle.youtube.hospitalManagement.entity.RefreshToken;
import com.codingshuttle.youtube.hospitalManagement.entity.User;
import com.codingshuttle.youtube.hospitalManagement.service.AuthService;
import com.codingshuttle.youtube.hospitalManagement.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.Response;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final RefreshTokenService refreshTokenService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@RequestBody LoginRequestDto loginRequestDto){
        return ResponseEntity.ok(authService.login(loginRequestDto));
    }

    @PostMapping("/signup")
    public ResponseEntity<Object> signup(@RequestBody SignupRequestDto signUp){
        return ResponseEntity.ok(authService.signup(signUp));
    }


    @PostMapping("/refresh-token")
    public ResponseEntity<Object>  refreshJwtToken(RefreshTokenRequestDto refreshTokenRequestDto){
        RefreshToken refreshToken = refreshTokenService.verifyRefreshToken(refreshTokenRequestDto.getRefreshToken());
        User user= refreshToken.getUser();
        String token = authService.getAccessToken(user);
        LoginResponseDto loginResponseDto = new LoginResponseDto(token,user.getId(),refreshToken.getRefreshToken());
        return ResponseEntity.ok(loginResponseDto);
    }
}
