package com.NoBugs.cognito_login.authentication;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class User {

    private String name;
    private String email;
    private String sub;

}
