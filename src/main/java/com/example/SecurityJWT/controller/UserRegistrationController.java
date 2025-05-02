package com.example.SecurityJWT.controller;

import com.example.SecurityJWT.entity.UserRegisterEntity;
import com.example.SecurityJWT.repository.UserRegistrationRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class UserRegistrationController {

    private final UserRegistrationRepository userAuthEntityRepository;
    private final PasswordEncoder passwordEncoder;

    UserRegistrationController(UserRegistrationRepository userAuthEntityRepository, PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
        this.userAuthEntityRepository = userAuthEntityRepository;
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody UserRegisterEntity userAuthEntity) {
        userAuthEntity.setPassword(passwordEncoder.encode(userAuthEntity.getPassword()));
        userAuthEntityRepository.save(userAuthEntity);
        return ResponseEntity.ok("User is Registered!!");
    }

    @GetMapping("/users")
    public String getUsersDetails() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return "fetched user details successfully";
    }
}
