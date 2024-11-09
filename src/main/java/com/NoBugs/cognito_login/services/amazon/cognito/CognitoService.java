package com.NoBugs.cognito_login.services.amazon.cognito;

import com.NoBugs.cognito_login.authentication.AuthenticationUser;
import com.NoBugs.cognito_login.utils.SignUpRequest;
import com.NoBugs.nobugs_exception.NoBugsException;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.*;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Map;


@Service
@Setter
@Getter
@Slf4j
public abstract class CognitoService<T extends AuthenticationUser> {

    private String poolId;

    private String clientId;

    private final AWSCognitoIdentityProvider cognitoClient;

    public CognitoService(AWSCognitoIdentityProvider cognitoClient) {
        this.cognitoClient = cognitoClient;
    }

    public AdminGetUserResult getUserBySub(String sub) {
        AdminGetUserRequest adminGetUserRequest = new AdminGetUserRequest();
        adminGetUserRequest.setUserPoolId(poolId);
        adminGetUserRequest.setUsername(sub);
        return cognitoClient.adminGetUser(adminGetUserRequest);
    }

    public GetUserResult getUser(String accessToken) {

        if (isTokenExpired(accessToken)) {
            throw new NoBugsException("Token is expired", HttpStatus.UNAUTHORIZED);
        }

        GetUserRequest getUserRequest = new GetUserRequest();
        getUserRequest.setAccessToken(accessToken);
        return cognitoClient.getUser(getUserRequest);

    }

    public InitiateAuthResult login(T authenticator) {
        return cognitoClient.initiateAuth(
                new InitiateAuthRequest()
                        .withClientId(clientId)
                        .withAuthFlow("USER_PASSWORD_AUTH")
                        .withAuthParameters(
                                Map.of("USERNAME", authenticator.getEmail(), "PASSWORD", authenticator.getPassword())
                        )
        );
    }

    public abstract SignUpResult signUp(T authenticator, List<AttributeType> attributes);

    public void confirmSignUp(String username, String confirmationCode) {
        ConfirmSignUpRequest confirmSignUpRequest = new ConfirmSignUpRequest();
        confirmSignUpRequest.setUsername(username);
        confirmSignUpRequest.setConfirmationCode(confirmationCode);
        confirmSignUpRequest.setClientId(clientId);
        cognitoClient.confirmSignUp(confirmSignUpRequest);
    }

    public UpdateUserAttributesResult updateUserAttributes(String accessToken, List<AttributeType> attributes) {

        if (isTokenExpired(accessToken)) {
            throw new NoBugsException("Token is expired", HttpStatus.UNAUTHORIZED);
        }

        UpdateUserAttributesRequest updateUserAttributesRequest = new UpdateUserAttributesRequest();
        updateUserAttributesRequest.setAccessToken(accessToken);
        updateUserAttributesRequest.setUserAttributes(attributes);

        return cognitoClient.updateUserAttributes(updateUserAttributesRequest);
    }

    public String forgotPasswordRequest(String username) {
        try {
            cognitoClient.forgotPassword(new ForgotPasswordRequest().withClientId(clientId).withUsername(username));
        } catch (Exception e) {
            throw new NoBugsException(e.getMessage(), HttpStatus.BAD_REQUEST);
        }

        return "Confirmation code sent to email";
    }

    public boolean checkConfirmationCode(String username, String confirmationCode) {
        try {
            cognitoClient.confirmForgotPassword(new ConfirmForgotPasswordRequest()
                    .withPassword("NewPassword123!")
                    .withClientId(clientId)
                    .withUsername(username)
                    .withConfirmationCode(confirmationCode));
        } catch (Exception e) {
            throw new NoBugsException(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
        return true;
    }

    public String changePassword(T authenticator) {
        try {
            cognitoClient.changePassword(new ChangePasswordRequest()
                    .withPreviousPassword("NewPassword123!")
                    .withProposedPassword(authenticator.getPassword())
                    .withAccessToken(login(authenticator).getAuthenticationResult().getAccessToken()
                    ));
        } catch (Exception e) {
            throw new NoBugsException(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
        return "Password changed successfully";
    }

    public AdminCreateUserResult signupSocialUser(SignUpRequest signUpRequest) {
        String passwordCustomer = signUpRequest.generatePassword();
        AdminCreateUserResult adminCreateUser;

        AdminCreateUserRequest createUserRequest = new AdminCreateUserRequest()
                .withUserPoolId(this.poolId)
                .withUsername(signUpRequest.getEmail())
                .withUserAttributes(
                        new AttributeType().withName("email").withValue(signUpRequest.getEmail()),
                        new AttributeType().withName("email_verified").withValue("true")
                )
                .withTemporaryPassword("")
                .withMessageAction("SUPPRESS");

        adminCreateUser = cognitoClient.adminCreateUser(createUserRequest);

        AdminSetUserPasswordRequest setPasswordRequest = new AdminSetUserPasswordRequest()
                .withUserPoolId(this.poolId)
                .withUsername(signUpRequest.getEmail())
                .withPassword(passwordCustomer)
                .withPermanent(true);

        cognitoClient.adminSetUserPassword(setPasswordRequest);
        log.info("User confirmed without forced password change.");

        return adminCreateUser;
    }

    public static String parseSubjectJWT(String token) {
        try {
            JWT jwt = JWTParser.parse(token);
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            return claims.getSubject();
        } catch (ParseException e) {
            throw new NoBugsException("Invalid token", HttpStatus.UNAUTHORIZED);
        }
    }

    public static boolean isTokenExpired(String token) {
        try {
            JWT jwt = JWTParser.parse(token);
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            Date expirationTime = claims.getExpirationTime();

            return expirationTime.before(new Date());
        } catch (ParseException e) {
            throw new NoBugsException("Invalid token", HttpStatus.UNAUTHORIZED);
        }
    }

}
