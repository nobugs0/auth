package com.NoBugs.cognito_login.authentication;

public interface AuthenticationUser {
    String getEmail();

    default String getPassword(){
        return "NewPassword123!";
    }
}
