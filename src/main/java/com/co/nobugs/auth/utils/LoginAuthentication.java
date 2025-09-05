package com.co.nobugs.auth.utils;

import com.co.nobugs.auth.authentication.AuthUser;
import com.co.nobugs.auth.authentication.AuthenticationUser;
import com.co.nobugs.auth.authentication.UserRepositoryImplementation;
import com.co.nobugs.auth.services.amazon.cognito.CognitoService;
import com.co.nobugs.nobugsexception.NoBugsException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;

@RequiredArgsConstructor
public class LoginAuthentication<T> {

    private final Class<T> response;

    public <R extends UserRepositoryImplementation<?>, A extends AuthenticationUser> AuthUser<?> login(A userAuthentication, R repository, CognitoService<A> cognitoService) throws NoBugsException {
        LoginHandler loginHandler = new LoginHandler(userAuthentication, repository);
        loginHandler.setInitiateAuthResult(loginHandler.login(userAuthentication, cognitoService));
        return loginHandler.loginUser(response);
    }

    @Setter
    private static final class LoginHandler {
        private InitiateAuthResponse initiateAuthResult;
        private AuthenticationUser userAuthentication;
        private UserRepositoryImplementation<?> repository;

        private LoginHandler(AuthenticationUser userAuthentication, UserRepositoryImplementation<?> repository) {
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

        private <R> AuthUser<R> loginUser(Class<R> userResponse) {
            return new AuthUser<>(
                    new ModelMapper().map(repository.findByEmail(userAuthentication.getEmail()), userResponse),
                    initiateAuthResult.authenticationResult().accessToken(),
                    initiateAuthResult.authenticationResult().refreshToken(),
                    initiateAuthResult.authenticationResult().idToken()
            );
        }
    }
}
