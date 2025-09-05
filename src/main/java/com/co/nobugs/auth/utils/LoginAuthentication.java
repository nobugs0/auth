package com.co.nobugs.auth.utils;

import com.co.nobugs.auth.authentication.AuthUser;
import com.co.nobugs.auth.authentication.AuthenticationUser;
import com.co.nobugs.auth.authentication.User;
import com.co.nobugs.auth.authentication.UserRepositoryImplementation;
import com.co.nobugs.auth.services.amazon.cognito.CognitoService;
import com.co.nobugs.nobugsexception.NoBugsException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;
import lombok.Setter;
import org.springframework.http.HttpStatus;

public class LoginAuthentication<T extends User> {

    public <R extends UserRepositoryImplementation<T>, A extends AuthenticationUser> AuthUser<T> login(A userAuthentication, R repository, CognitoService<A> cognitoService) throws NoBugsException {
        LoginHandler<T> loginHandler = new LoginHandler<>(userAuthentication, repository);
        loginHandler.setInitiateAuthResult(loginHandler.login(userAuthentication, cognitoService));
        return loginHandler.loginUser();
    }

    @Setter
    private static final class LoginHandler<R extends User> {
        private InitiateAuthResponse initiateAuthResult;
        private AuthenticationUser userAuthentication;
        private UserRepositoryImplementation<R> repository;

        private LoginHandler(AuthenticationUser userAuthentication, UserRepositoryImplementation<R> repository) {
            this.userAuthentication = userAuthentication;
            this.repository = repository;
        }

        private <A extends AuthenticationUser> InitiateAuthResponse login(A userAuthentication, CognitoService<A> cognitoService) throws NoBugsException {
            try {
                return cognitoService.login(userAuthentication);
            } catch (Exception e) {
                throw new NoBugsException(e.getMessage(), HttpStatus.BAD_REQUEST);
            }
        }

        private AuthUser<R> loginUser() {
            return new AuthUser<>(
                    repository.findByEmail(userAuthentication.getEmail()),
                    initiateAuthResult.authenticationResult().accessToken(),
                    initiateAuthResult.authenticationResult().refreshToken(),
                    initiateAuthResult.authenticationResult().idToken()
            );
        }
    }
}
