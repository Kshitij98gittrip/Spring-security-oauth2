package com.codingshuttle.youtube.hospitalManagement.service;

import com.codingshuttle.youtube.hospitalManagement.dto.LoginRequestDto;
import com.codingshuttle.youtube.hospitalManagement.dto.LoginResponseDto;
import com.codingshuttle.youtube.hospitalManagement.dto.SignUpResponseDto;
import com.codingshuttle.youtube.hospitalManagement.entity.AuthProviderType;
import com.codingshuttle.youtube.hospitalManagement.entity.User;
import com.codingshuttle.youtube.hospitalManagement.entity.UserRepository;
import com.codingshuttle.youtube.hospitalManagement.security.AuthUtil;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.Response;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service

public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final AuthUtil authUtil;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthService(AuthenticationManager authenticationManager, AuthUtil authUtil, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.authUtil = authUtil;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }


    public LoginResponseDto login(LoginRequestDto loginRequestDto) {

        Authentication authentication =    authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequestDto.getUserName(), loginRequestDto.getPassword())
        );

        User user = (User) authentication.getPrincipal();

        //To create JWT we need dependencies jjwt
        String token = authUtil.generateAccessToken(user);
        return new LoginResponseDto(token, user.getId());
    }

    public SignUpResponseDto signup(LoginRequestDto dto) {
        User user = signUpInternal(dto, AuthProviderType.EMAIL, null);

        return new SignUpResponseDto(user.getId(), user.getUsername());

    }

    public User signUpInternal(LoginRequestDto dto, AuthProviderType providerType, String providerId){
        User user = userRepository.findByUserName(dto.getUserName()).orElse(null);
        if(user!=null){
            throw new IllegalArgumentException("User exists");
        }

        user = User.builder()
                .userName(dto.getUserName())
                .providerId(providerId)
                .providerType(providerType)
                .build();

        if(providerType==providerType.EMAIL){
            user.setPassword(passwordEncoder.encode(dto.getPassword()));
        }

        return userRepository.save(user);
    }

    @Transactional
    public ResponseEntity<LoginResponseDto> handleOAuth2LoginRequest(OAuth2User oAuth2User, String registrationId){
        //find the providerType and providerId (From the auth util )
        AuthProviderType providerType = authUtil.getProviderTypeFromRegistrationId(registrationId);
        String providerId = authUtil.determineProviderIdFromOAuth2User(oAuth2User, registrationId);

        User user = userRepository.findByProviderIdAndProviderType(providerId, providerType).orElse(null);

        String email = oAuth2User.getAttribute("email");
        User emailUser = userRepository.findByUserName(email).orElse(null);

        //save the providerType and providerId info with user
        //if the user has an account directly login otherwise signup and then login

        if(user == null && emailUser ==null){
            //signup flow:
            String usrname =authUtil.determineUsernameFromOAuth2User(oAuth2User, registrationId, providerId);
            user = signUpInternal(new LoginRequestDto(usrname, null),providerType, providerId);

        }else if(user != null){
            if(email !=null && !email.isBlank() && !email.equals(user.getUsername())){
                user.setUserName(email);
                userRepository.save(user);
            }

        }else {
            throw new BadCredentialsException("This email is already exist with provider " + email + "email provider type");
        }
        LoginResponseDto loginResponseDto = new LoginResponseDto(authUtil.generateAccessToken(user), user.getId());
        return ResponseEntity.ok(loginResponseDto);
        }
}
