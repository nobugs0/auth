package com.NoBugs.cognito_login.services.amazon.cognito;

import com.NoBugs.cognito_login.authentication.AuthenticationUser;
import com.NoBugs.nobugs_exception.NoBugsException;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.AttributeType;
import com.amazonaws.services.cognitoidp.model.SignUpRequest;
import com.amazonaws.services.cognitoidp.model.SignUpResult;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CognitoSignUpConfirmEmail<T extends AuthenticationUser> extends CognitoService<T>{

    public CognitoSignUpConfirmEmail(AWSCognitoIdentityProvider cognitoClient) {
        super(cognitoClient);
    }

    @Override
    public SignUpResult signUp(T authenticationUser, List<AttributeType> attributes) {
        SignUpRequest signUpRequest = new SignUpRequest();
        signUpRequest.setClientId(super.getClientId());
        signUpRequest.setUsername(authenticationUser.getEmail());
        signUpRequest.setPassword(authenticationUser.getPassword());
        signUpRequest.setUserAttributes(attributes);

        SignUpResult signUpResult;

        try{
            signUpResult = getCognitoClient().signUp(signUpRequest);
        } catch (Exception e) {
            throw new NoBugsException(e.getMessage(), HttpStatus.BAD_REQUEST);
        }

        return signUpResult;
    }
}
