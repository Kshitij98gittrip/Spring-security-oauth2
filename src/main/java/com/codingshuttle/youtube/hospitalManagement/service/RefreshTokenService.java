package com.codingshuttle.youtube.hospitalManagement.service;

import com.codingshuttle.youtube.hospitalManagement.entity.RefreshToken;
import com.codingshuttle.youtube.hospitalManagement.entity.User;
import com.codingshuttle.youtube.hospitalManagement.entity.UserRepository;
import com.codingshuttle.youtube.hospitalManagement.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    public long tokenValidity = 5*60*60*1000;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    public RefreshToken createRefreshToken(String username){

        User user = userRepository.findByUserName(username).orElse(null);
        RefreshToken refreshToken =  user.getRefreshToken();
        if(refreshToken==null) {
             refreshToken = RefreshToken.builder().refreshToken(UUID.randomUUID().toString())
                    .expiry(Instant.now().plusMillis(tokenValidity))
                    .user(user)
                    .build();
        }else{
            refreshToken.setExpiry(Instant.now().plusMillis(tokenValidity));
        }

        user.setRefreshToken(refreshToken);

        refreshTokenRepository.save(refreshToken);
        return refreshToken;
    }

    public RefreshToken verifyRefreshToken(String refreshToken){
         RefreshToken refreshToken1 = refreshTokenRepository.findByRefreshToken(refreshToken).orElseThrow(
                 ()->new RuntimeException("Refresh Token not found"));
         if(refreshToken1.getExpiry().compareTo(Instant.now())<0){
             refreshTokenRepository.delete(refreshToken1);
             throw new RuntimeException("Refresh Token Expired");
         }else{
             return refreshToken1;
         }
    }

}
