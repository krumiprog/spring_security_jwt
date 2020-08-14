package org.example.springsecurityjwt.controller;

import org.example.springsecurityjwt.model.User;
import org.example.springsecurityjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@CrossOrigin
public class MainController {

    private final UserRepository userRepository;

    @Autowired
    public MainController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @RequestMapping("hello")
    public String getHello() {
        return "Hello";
    }

    @RequestMapping("api/admin/users")
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }
}
