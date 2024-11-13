package com.NoBugs.cognito_login.authentication;

import lombok.Getter;
import lombok.Setter;
import org.clubhive.enums.AuthType;

@Getter
@Setter
public class SocialUserAuthenticationDTO {
    private String socialToken;
    private String authType;
}