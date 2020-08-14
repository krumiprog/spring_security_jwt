package org.example.springsecurityjwt.service;

import org.example.springsecurityjwt.model.User;
import org.example.springsecurityjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;

@Service
public class InitDatabase implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public InitDatabase(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {

        User userOne = new User("user", passwordEncoder.encode("password"), "USER");
        User userTwo = new User("admin", passwordEncoder.encode("password"), "ADMIN");

        userRepository.saveAll(Arrays.asList(userOne, userTwo));
    }
}
