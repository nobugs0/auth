package com.NoBugs.cognito_login.utils;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.NoBugs.cognito_login.authentication.AuthenticationUser;
import com.NoBugs.nobugs_exception.NoBugsException;
import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;

@Getter
@Setter
public class SignUpRequest {

    private String prefix;
    private String suffix;
    private AuthenticationUser authenticationUser;

    public String getEmailPrefix() {
        if (getAuthenticationUser() == null || getAuthenticationUser().getEmail() == null) {
            throw new NoBugsException("Some fields are required", HttpStatus.BAD_REQUEST);
        }

        String email = getAuthenticationUser().getEmail();
        return email.substring(0, email.indexOf("@"));
    }

    public String generatePassword() {
        BCrypt.Hasher bCrypt = BCrypt.withDefaults();
        return bCrypt.hashToString(BCrypt.SALT_LENGTH, (prefix + getEmailPrefix() + suffix).toCharArray());
    }

    public String getEmail() {
        if (authenticationUser == null || authenticationUser.getEmail() == null)
            throw new NoBugsException("authenticationUser or email is null", HttpStatus.BAD_REQUEST);

        return authenticationUser.getEmail();
    }

}