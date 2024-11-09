package com.NoBugs.cognito_login.utils;

import com.NoBugs.cognito_login.authentication.AuthenticationUser;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PasswordRequest {

    private String prefix;
    private String sufix;
    private AuthenticationUser authenticationUser;

}
