package com.example.SecurityJWT.repository;

import com.example.SecurityJWT.entity.UserRegisterEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRegistrationRepository extends JpaRepository<UserRegisterEntity, Long> {

    Optional<UserRegisterEntity> findByUsername(String userName);
}
