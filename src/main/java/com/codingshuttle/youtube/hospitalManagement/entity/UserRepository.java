package com.codingshuttle.youtube.hospitalManagement.entity;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUserName(String username);
    Optional<User> findByProviderIdAndProviderType(String providerId, AuthProviderType providerType);
}