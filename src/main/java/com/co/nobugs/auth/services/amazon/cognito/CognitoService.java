package com.co.nobugs.auth.services.amazon.cognito;

import com.co.nobugs.auth.authentication.AuthenticationUser;
import com.co.nobugs.auth.utils.SignUpRequest;
import com.co.nobugs.nobugsexception.NoBugsException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;
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


@Setter
@Getter
@Slf4j
@Service
@RequiredArgsConstructor
public abstract class CognitoService<T extends AuthenticationUser> {

    private final CognitoIdentityProviderClient cognitoClient;

    @Value("${aws.cognito.userPoolId}")
    private String poolId;

    @Value("${aws.cognito.clientId}")
    private String clientId;

    public GetUserResponse getUser(String accessToken) throws NoBugsException {
        if (isTokenExpired(accessToken)) {
            throw new NoBugsException("Token is expired", HttpStatus.UNAUTHORIZED);
        }

        GetUserRequest request = GetUserRequest.builder()
                .accessToken(accessToken)
                .build();

        return cognitoClient.getUser(request);
    }

    public AdminGetUserResponse getUserBySub(String sub) {
        AdminGetUserRequest request = AdminGetUserRequest.builder()
                .userPoolId(poolId)
                .username(sub)
                .build();

        return cognitoClient.adminGetUser(request);
    }

    public InitiateAuthResponse login(T user) {
        InitiateAuthRequest request = InitiateAuthRequest.builder()
                .authFlow(AuthFlowType.USER_PASSWORD_AUTH)
                .clientId(clientId)
                .authParameters(Map.of(
                        "USERNAME", user.getEmail(),
                        "PASSWORD", user.getPassword()
                ))
                .build();

        return cognitoClient.initiateAuth(request);
    }

    public void confirmSignUp(String username, String confirmationCode) {
        ConfirmSignUpRequest request = ConfirmSignUpRequest.builder()
                .username(username)
                .confirmationCode(confirmationCode)
                .clientId(clientId)
                .build();

        cognitoClient.confirmSignUp(request);
    }

    // Continúa migrando los otros métodos de forma similar...

    public UpdateUserAttributesResponse updateUserAttributes(String accessToken, List<AttributeType> attributes) throws NoBugsException {
        if (isTokenExpired(accessToken)) {
            throw new NoBugsException("Token is expired", HttpStatus.UNAUTHORIZED);
        }

        UpdateUserAttributesRequest request = UpdateUserAttributesRequest.builder()
                .accessToken(accessToken)
                .userAttributes(attributes)
                .build();

        return cognitoClient.updateUserAttributes(request);
    }


    public String forgotPasswordRequest(String username) throws NoBugsException {
        try {
            ForgotPasswordRequest request = ForgotPasswordRequest.builder()
                    .clientId(clientId)
                    .username(username)
                    .build();

            cognitoClient.forgotPassword(request);
            return "Confirmation code sent to email";
        } catch (CognitoIdentityProviderException e) {
            throw new NoBugsException(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }


    public boolean checkConfirmationCode(String username, String confirmationCode) throws NoBugsException {
        SignUpRequest signUpRequest = new SignUpRequest();
        signUpRequest.setAuthenticationUser(() -> username);

        try {
            ConfirmForgotPasswordRequest request = ConfirmForgotPasswordRequest.builder()
                    .clientId(clientId)
                    .username(username)
                    .confirmationCode(confirmationCode)
                    .password(signUpRequest.generatePassword())
                    .build();

            cognitoClient.confirmForgotPassword(request);
            return true;
        } catch (CognitoIdentityProviderException e) {
            throw new NoBugsException(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }


    public String changePassword(T authenticator) throws NoBugsException {
        SignUpRequest signUpRequest = new SignUpRequest();
        signUpRequest.setAuthenticationUser(authenticator);
        String temporaryPassword = signUpRequest.generatePassword();

        AuthenticationUser oldUser = new AuthenticationUser() {
            @Override
            public String getEmail() {
                return authenticator.getEmail();
            }

            @Override
            public String getPassword() {
                return temporaryPassword;
            }
        };

        try {
            String token = login((T) oldUser).authenticationResult().accessToken();

            ChangePasswordRequest request = ChangePasswordRequest.builder()
                    .previousPassword(temporaryPassword)
                    .proposedPassword(authenticator.getPassword())
                    .accessToken(token)
                    .build();

            cognitoClient.changePassword(request);
            return "Password changed successfully";
        } catch (CognitoIdentityProviderException e) {
            throw new NoBugsException(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }


    public AdminCreateUserResponse signupSocialUser(SignUpRequest signUpRequest) throws NoBugsException {
        String passwordCustomer = signUpRequest.generatePassword();

        try {
            AdminCreateUserRequest createUserRequest = AdminCreateUserRequest.builder()
                    .userPoolId(poolId)
                    .username(signUpRequest.getEmail())
                    .userAttributes(
                            software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType.builder()
                                    .name("email").value(signUpRequest.getEmail()).build(),
                            software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType.builder()
                                    .name("email_verified").value("true").build()
                    )
                    .temporaryPassword(passwordCustomer)
                    .messageAction("SUPPRESS")
                    .build();

            AdminCreateUserResponse response = cognitoClient.adminCreateUser(createUserRequest);

            AdminSetUserPasswordRequest setPasswordRequest = AdminSetUserPasswordRequest.builder()
                    .userPoolId(poolId)
                    .username(signUpRequest.getEmail())
                    .password(passwordCustomer)
                    .permanent(true)
                    .build();

            cognitoClient.adminSetUserPassword(setPasswordRequest);

            log.info("User confirmed without forced password change.");
            return response;

        } catch (CognitoIdentityProviderException e) {
            throw new NoBugsException(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }


    public static String parseSubjectJWT(String token) throws NoBugsException {
        try {
            JWT jwt = JWTParser.parse(token);
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            return claims.getSubject();
        } catch (ParseException e) {
            throw new NoBugsException("Invalid token", HttpStatus.UNAUTHORIZED);
        }
    }

    public static boolean isTokenExpired(String token) throws NoBugsException {
        try {
            JWT jwt = JWTParser.parse(token);
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            Date expirationTime = claims.getExpirationTime();

            return expirationTime.before(new Date());
        } catch (ParseException e) {
            throw new NoBugsException("Invalid token", HttpStatus.UNAUTHORIZED);
        }
    }

    public abstract SignUpResponse signUp(T authenticationUser, List<AttributeType> attributes) throws NoBugsException;
}
