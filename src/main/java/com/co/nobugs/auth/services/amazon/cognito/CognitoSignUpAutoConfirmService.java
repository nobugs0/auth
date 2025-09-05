package com.co.nobugs.auth.services.amazon.cognito;

import com.co.nobugs.auth.authentication.AuthenticationUser;
import com.co.nobugs.nobugsexception.NoBugsException;
import org.springframework.http.HttpStatus;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.util.List;

public class CognitoSignUpAutoConfirmService<T extends AuthenticationUser> extends CognitoService<T> {

    public CognitoSignUpAutoConfirmService(String poolId, String clientId, String clientSecret, CognitoIdentityProviderClient cognitoClient) {
        super(poolId, clientId, clientSecret, cognitoClient);
    }

    @Override
    public SignUpResponse signUp(T authenticationUser, List<AttributeType> attributes) throws NoBugsException {
        SignUpRequest signUpRequest = SignUpRequest.builder()
                .clientId(getClientId())
                .username(authenticationUser.getEmail())
                .password(authenticationUser.getPassword())
                .secretHash(getSecretHash(authenticationUser.getEmail()))
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
                .username(authenticationUser.getEmail())
                .build();

        getCognitoClient().adminConfirmSignUp(adminConfirmSignUpRequest);

        return signUpResult;
    }
}