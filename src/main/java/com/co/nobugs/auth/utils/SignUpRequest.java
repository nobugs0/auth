package com.co.nobugs.auth.utils;

import com.co.nobugs.auth.authentication.AuthenticationUser;
import com.co.nobugs.nobugsexception.NoBugsException;
import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Getter
@Setter
public class SignUpRequest {

    private String prefix;
    private String suffix;
    private AuthenticationUser authenticationUser;

    public String getEmailPrefix() throws NoBugsException {
        if (getAuthenticationUser() == null || getAuthenticationUser().getEmail() == null) {
            throw new NoBugsException("Some fields are required", HttpStatus.BAD_REQUEST);
        }

        String email = getAuthenticationUser().getEmail();
        return email.substring(0, email.indexOf("@"));
    }

    public String generatePassword() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest((prefix + getEmailPrefix() + suffix).getBytes(StandardCharsets.UTF_8));
            return bytesToHex(encodedhash);
        } catch (NoSuchAlgorithmException | NoBugsException e) {
            throw new RuntimeException(e);
        }
    }

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public String getEmail() throws NoBugsException {
        if (authenticationUser == null || authenticationUser.getEmail() == null)
            throw new NoBugsException("authenticationUser or email is null", HttpStatus.BAD_REQUEST);

        return authenticationUser.getEmail();
    }

}