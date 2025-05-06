package com.co.nobugs.auth.services.amazon.cognito;

import com.co.nobugs.auth.authentication.AuthenticationUser;
import com.co.nobugs.nobugsexception.NoBugsException;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.AdminConfirmSignUpRequest;
import com.amazonaws.services.cognitoidp.model.AttributeType;
import com.amazonaws.services.cognitoidp.model.SignUpRequest;
import com.amazonaws.services.cognitoidp.model.SignUpResult;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CognitoSignUpAutoConfirmService<T extends AuthenticationUser> extends CognitoService<T> {

    public CognitoSignUpAutoConfirmService(AWSCognitoIdentityProvider cognitoClient) {
        super(cognitoClient);
    }

    @Override
    public SignUpResult signUp(T authenticationUser, List<AttributeType> attributes) throws NoBugsException {
        SignUpRequest signUpRequest = new SignUpRequest();
        signUpRequest.setClientId(getClientId());
        signUpRequest.setUsername(authenticationUser.getEmail());
        signUpRequest.setPassword(authenticationUser.getPassword());
        signUpRequest.setUserAttributes(attributes);

        SignUpResult signUpResult;
        try {
            signUpResult = getCognitoClient().signUp(signUpRequest);
        } catch (Exception e) {
            throw new NoBugsException(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
        signUpResult.setUserConfirmed(true);
        AdminConfirmSignUpRequest adminConfirmSignUpRequest = new AdminConfirmSignUpRequest()
                .withUserPoolId(getPoolId())
                .withUsername(signUpResult.getUserSub());
        getCognitoClient().adminConfirmSignUp(adminConfirmSignUpRequest);
        return signUpResult;
    }

}
