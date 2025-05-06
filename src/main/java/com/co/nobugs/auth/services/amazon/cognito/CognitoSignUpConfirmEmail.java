package com.co.nobugs.auth.services.amazon.cognito;

import com.co.nobugs.auth.authentication.AuthenticationUser;
import com.co.nobugs.nobugsexception.NoBugsException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CognitoSignUpConfirmEmail<T extends AuthenticationUser> extends CognitoService<T> {

    private final CognitoIdentityProviderClient cognitoClient;

    public CognitoSignUpConfirmEmail(CognitoIdentityProviderClient cognitoClient) {
        super(cognitoClient);
        this.cognitoClient = cognitoClient;
    }

    @Override
    public SignUpResponse signUp(T authenticationUser, List<AttributeType> attributes) throws NoBugsException {
        SignUpRequest signUpRequest = SignUpRequest.builder()
                .clientId(super.getClientId())
                .username(authenticationUser.getEmail())
                .password(authenticationUser.getPassword())
                .userAttributes(attributes)
                .build();

        SignUpResponse signUpResult;

        try {
            signUpResult = cognitoClient.signUp(signUpRequest);
        } catch (Exception e) {
            throw new NoBugsException(e.getMessage(), HttpStatus.BAD_REQUEST);
        }

        return signUpResult;
    }
}
