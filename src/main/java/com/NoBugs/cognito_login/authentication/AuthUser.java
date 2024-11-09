package com.NoBugs.cognito_login.authentication;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class AuthUser<T> {
    private T user;
    private String accessToken;
    private String idToken;
}
