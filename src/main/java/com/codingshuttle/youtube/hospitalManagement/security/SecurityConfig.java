package com.codingshuttle.youtube.hospitalManagement.security;

import com.codingshuttle.youtube.hospitalManagement.entity.type.RoleType;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

//    private final PasswordEncoder passwordEncoder;
    private final JwtAuthFilter jwtAuthFilter;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;
    private final HandlerExceptionResolver handlerExceptionResolver;


    @Bean //singleton bean
    /// This is done before the controller level
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sessionConfig->
                        sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //as in stateless we dont store any info
                .authorizeHttpRequests(auth ->auth
                        .requestMatchers("/public/**","/auth/**").permitAll()
                        .requestMatchers("/admin/**").hasRole(RoleType.ADMIN.name())
                        .requestMatchers("/doctors/**").hasAnyRole(RoleType.DOCTOR.name(), RoleType.ADMIN.name())
                        .anyRequest().authenticated()

                )
                /**
                 * In this jwtFilter is added before UsernamePasswordAuthenticationFilter because
                 * our app must first check Is JWT token valid?
                 * UsernamePasswordAuthenticationFilter is Spring’s default filter for login using username/password.
                 * But after login, users do NOT send username/password again. They send JWT token:
                 * So JWT should be checked FIRST.That’s why:
                 * Before Spring checks username/password,
                 * first check JWT token.
                 *
                 * Simple real-life analogy:
                 * Imagine airport security.
                 * Order should be:
                 * 1. Check passport (JWT)
                 * 2. Then allow entry
                 *
                 *p
                 * */
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                //OAuth 2 configuration
                .oauth2Login(oauth2 ->oauth2
                .failureHandler((AuthenticationFailureHandler) (request, response, exception) -> {
                            log.error("OAuth2 error {}", exception.getMessage());
                        })
                .successHandler(oAuth2SuccessHandler)
                )
                .exceptionHandling(exConfig ->
                        exConfig.accessDeniedHandler((AccessDeniedHandler)
                                (request, response, accessDeniedException) -> {
                        handlerExceptionResolver.resolveException(request,response, null,accessDeniedException);
                        }));
//                .formLogin(Customizer.withDefaults()); //dont need this and this stores the session
        return httpSecurity.build(); //will give another security filter chain
    }

    /**
     * This is from the spring security
     * and it is handled by spring only
     * This method handles in memory authentication and users internam UserDetails class impl
     * */
//    @Bean
//    UserDetailsService userDetailsService(){
//        UserDetails user1 = User.withUsername("admin")
//                .password(passwordEncoder.encode("pass")) //we can't directly store password we have to define and encoder
//                .roles("ADMIN")
//                .build();
//
//        UserDetails user2 = User.withUsername("doctor")
//                .password(passwordEncoder.encode("doctor"))
//                .roles("DOCTOR")
//                .build();
//
//        return new InMemoryUserDetailsManager(user1, user2);
//    }


    /**
     * To use our own dao Users entity we have create new bean of dao
     * */


}
