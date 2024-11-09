package com.NoBugs.cognito_login.authentication;

public interface AuthtenticationUser {
    String getEmail();

    default String getPassword(){
        return "NewPassword123!";
    }
}
