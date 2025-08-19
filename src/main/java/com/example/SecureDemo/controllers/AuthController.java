package com.example.SecureDemo.controllers;

import com.example.SecureDemo.service.JwtService;
import com.example.SecureDemo.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationManager authManager;
    private final JwtService jwtService;
    private final UserService userService;

    @PostMapping("/register")
    public String register(@RequestParam String username,
                           @RequestParam String password,
                           @RequestParam(defaultValue = "USER") String role) {
        userService.registerUser(username, password, "ROLE_" + role.toUpperCase());
        return "User registered";
    }

    @PostMapping("/login")
    public Map<String, String> login(@RequestParam String username,
                                     @RequestParam String password) {
        Authentication auth = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password));
        String token = jwtService.generateToken(username);
        return Map.of("token", token);
    }

    @GetMapping("/hello")
    public String hello() {
        return "Hello, authenticated user!";
    }
}
