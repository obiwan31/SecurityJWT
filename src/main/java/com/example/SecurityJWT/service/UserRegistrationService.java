package com.example.SecurityJWT.service;

import com.example.SecurityJWT.entity.UserRegisterEntity;
import com.example.SecurityJWT.repository.UserRegistrationRepository;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserRegistrationService implements UserDetailsService {

    private final UserRegistrationRepository userRegistrationRepository;

    public UserRegistrationService(UserRegistrationRepository userRegistrationRepository) {
        this.userRegistrationRepository = userRegistrationRepository;
    }

    @Override
    public UserRegisterEntity loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRegistrationRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found!!"));
    }


}
