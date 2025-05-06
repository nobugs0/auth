package com.co.nobugs.auth.authentication;

public interface AuthenticationUser {
    String getEmail();

    default String getPassword(){
        return "NewPassword123!";
    }
}
