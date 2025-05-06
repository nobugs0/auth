package com.co.nobugs.auth.services.amazon.cognito;

import com.co.nobugs.auth.authentication.AuthenticationUser;
import com.co.nobugs.nobugsexception.NoBugsException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.util.List;

@Service
@Slf4j
public class CognitoSignUpAutoConfirmService<T extends AuthenticationUser> extends CognitoService<T> {

    public CognitoSignUpAutoConfirmService(CognitoIdentityProviderClient cognitoClient) {
        super(cognitoClient);
    }

    @Override
    public SignUpResponse signUp(T authenticationUser, List<AttributeType> attributes) throws NoBugsException {
        SignUpRequest signUpRequest = SignUpRequest.builder()
                .clientId(getClientId())
                .username(authenticationUser.getEmail())
                .password(authenticationUser.getPassword())
                .userAttributes(attributes)
                .build();

        SignUpResponse signUpResult;
        try {
            signUpResult = getCognitoClient().signUp(signUpRequest);
        } catch (CognitoIdentityProviderException e) {
            throw new NoBugsException(e.awsErrorDetails().errorMessage(), HttpStatus.BAD_REQUEST);
        }

        AdminConfirmSignUpRequest adminConfirmSignUpRequest = AdminConfirmSignUpRequest.builder()
                .userPoolId(getPoolId())
                .username(authenticationUser.getEmail()) // NO usar getUserSub(), es el ID interno, no el username
                .build();

        getCognitoClient().adminConfirmSignUp(adminConfirmSignUpRequest);

        return signUpResult;
    }
}