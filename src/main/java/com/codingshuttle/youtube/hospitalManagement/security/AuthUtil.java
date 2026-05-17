package com.codingshuttle.youtube.hospitalManagement.security;

import com.codingshuttle.youtube.hospitalManagement.entity.AuthProviderType;
import com.codingshuttle.youtube.hospitalManagement.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Date;

@Component
@Slf4j
public class AuthUtil {

    // All three components of JWT

    //secret key
    @Value("${jwt.secret.key}")
    private String jwtSecretKey;

    //Creating secret keyobject
    //header component
    private SecretKey getSecretKey(){
        return Keys.hmacShaKeyFor(jwtSecretKey.getBytes(StandardCharsets.UTF_8));
    }

    //payload
    public String generateAccessToken(User user){
        return Jwts.builder()
                .subject(user.getUsername())
                .claim("userId", user.getId().toString())
                .issuedAt(new Date())
                //access token should have short live use refresh token
                .expiration(new Date(System.currentTimeMillis()+1000*60*10))
                .signWith(getSecretKey())
                .compact();
    }

    //Extracting username from the token
    public String getUsernameFromToken(String token) {

        Claims claims = Jwts.parser()
                .verifyWith(getSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims.getSubject();
    }

    public AuthProviderType getProviderTypeFromRegistrationId(String registrationId){
        return switch (registrationId.toLowerCase()){
            case "google" -> AuthProviderType.GOOGLE;
            case "github" -> AuthProviderType.GITHUB;
            case "facebook" -> AuthProviderType.FACEBOOK;
            default -> throw new IllegalArgumentException("Unsupported OAuth2 provider: "+ registrationId);
        };
    }

    public String determineProviderIdFromOAuth2User(OAuth2User oAuth2User, String registrationId){
        String providerId = switch (registrationId.toLowerCase()){
            case "google"-> oAuth2User.getAttribute("sub");
            case "github"-> oAuth2User.getAttribute("id").toString();
            default -> {
                log.error("Unsupported OAuht2 Provider : {}",registrationId);
                throw new IllegalArgumentException("Unsupported OAuht2 Provider : " +registrationId);
            }
        };

        if(providerId==null || providerId.isBlank()){
            log.error("Unable to determine providerId for reg {}", registrationId);
            throw new IllegalArgumentException("Unable to determine providerId for reg : " +registrationId);

        }

        return providerId;
    }

    public String determineUsernameFromOAuth2User(OAuth2User oAuth2User, String registrationId, String providerId){
        String email = oAuth2User.getAttribute("email");
        if(email!=null && !email.isBlank())return email;

        return switch (registrationId.toLowerCase()){
           case "google" -> oAuth2User.getAttribute("sub");
           case "github" -> oAuth2User.getAttribute("login");
           default -> providerId;
        };
    }
}
