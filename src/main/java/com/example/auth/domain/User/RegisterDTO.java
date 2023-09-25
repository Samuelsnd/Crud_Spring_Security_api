package com.example.auth.domain.User;

public record RegisterDTO(String login, String password, UserRole role) {
}
