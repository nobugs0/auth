package com.NoBugs.cognito_login.authentication;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SocialUserAuthenticationDTO {
    private String socialToken;
    private String authType;
}