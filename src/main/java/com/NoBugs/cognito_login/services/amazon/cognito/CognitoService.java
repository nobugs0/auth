package com.clubhive.organizers.services.amazon.cognito;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.*;
import com.clubhive.organizers.utils.CognitoUtils;
import com.clubhive.organizers.utils.ExceptionHandler;
import exceptions.NoBugsException;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.clubhive.DTO.auth.CustomerResponseDTO;
import org.clubhive.utils.CustomJWTParser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.List;


@Service
@Setter
@Getter
@Slf4j
public abstract class CognitoService {

    private String poolId;

    private String clientId;

    private final AWSCognitoIdentityProvider cognitoClient;

    @Autowired
    private ExceptionHandler exceptionHandler;

    private final String TEMPORAL_PASSWD = "CHTemporalPasswd123*";
    private final String PERMANENT_PASSWD = "PermanentPassword123!"; // TO-DO: Cambiar esta pass por algun ID que devuelva google.

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
        if (CustomJWTParser.isTokenExpired(accessToken)) {
            throw new NoBugsException("Token is expired", HttpStatus.UNAUTHORIZED);
        }

        GetUserRequest getUserRequest = new GetUserRequest();
        getUserRequest.setAccessToken(accessToken);
        return cognitoClient.getUser(getUserRequest);
    }

    public InitiateAuthResult login(String username, String password) {
        return cognitoClient.initiateAuth(CognitoUtils.createInitiateAuthRequest(clientId, username, password));
    }

    public abstract SignUpResult signUp(String username, String password, List<AttributeType> attributes);

    public void confirmSignUp(String username, String confirmationCode) {

        ConfirmSignUpRequest confirmSignUpRequest = new ConfirmSignUpRequest();
        confirmSignUpRequest.setUsername(username);
        confirmSignUpRequest.setConfirmationCode(confirmationCode);
        confirmSignUpRequest.setClientId(clientId);
        cognitoClient.confirmSignUp(confirmSignUpRequest);
    }

    public UpdateUserAttributesResult updateUserAttributes(String accessToken, List<AttributeType> attributes) {

        if (CustomJWTParser.isTokenExpired(accessToken)) {
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
            exceptionHandler.handleConfirmMailException(e);
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
            exceptionHandler.handleConfirmMailException(e);
        }
        return true;
    }

    public String changePassword(String username, String newPassword) {

        try {
            cognitoClient.changePassword(new ChangePasswordRequest()
                    .withPreviousPassword("NewPassword123!")
                    .withProposedPassword(newPassword)
                    .withAccessToken(login(username, "NewPassword123!").getAuthenticationResult().getAccessToken()
                    ));
        } catch (Exception e) {
            exceptionHandler.handleConfirmMailException(e);
        }
        return "Password changed successfully";
    }

    public AdminCreateUserResult signupSocialUser(CustomerResponseDTO customer) {

        String passwordCustomer = CognitoUtils.generatePasswordById(customer.getDni());
        AdminCreateUserResult adminCreateUser;

        AdminCreateUserRequest createUserRequest = new AdminCreateUserRequest()
                .withUserPoolId(this.poolId)
                .withUsername(customer.getEmail())
                .withUserAttributes(
                        new AttributeType().withName("email").withValue(customer.getEmail()),
                        new AttributeType().withName("email_verified").withValue("true")
                )
                .withTemporaryPassword(TEMPORAL_PASSWD)
                .withMessageAction("SUPPRESS");

        adminCreateUser = cognitoClient.adminCreateUser(createUserRequest);

        AdminSetUserPasswordRequest setPasswordRequest = new AdminSetUserPasswordRequest()
                .withUserPoolId(this.poolId)
                .withUsername(customer.getEmail())
                .withPassword(passwordCustomer)
                .withPermanent(true);

        cognitoClient.adminSetUserPassword(setPasswordRequest);
        log.info("User confirmed without forced password change.");

        return adminCreateUser;
    }




}
