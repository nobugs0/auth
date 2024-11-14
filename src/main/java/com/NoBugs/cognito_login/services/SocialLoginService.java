package com.NoBugs.cognito_login.services;

import com.NoBugs.cognito_login.authentication.SocialUserAuthenticationDTO;
import com.NoBugs.cognito_login.services.interfaces.SocialAuthToken;
import com.NoBugs.cognito_login.services.social.tokens.FacebookAuthToken;
import com.NoBugs.cognito_login.services.social.tokens.GoogleAuthToken;
import com.NoBugs.nobugs_exception.NoBugsException;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Collections;

@Slf4j
@Service
public class SocialLoginService {

    @Value("${google.idClient}")
    private String GOOGLE_CLIENT_ID; // Reemplaza con tu ID de cliente de Google
    private static final String FACEBOOK_GRAPH_URL = "https://graph.facebook.com/me?fields=id,name,email&access_token=";

    private static final GsonFactory JSON_FACTORY = GsonFactory.getDefaultInstance();
    public SocialAuthToken socialLogin(SocialUserAuthenticationDTO authentication) {

        return switch (authentication.getAuthType()) {
            case "GOOGLE" -> googleLogin(authentication);
            case "FACEBOOK" -> facebookLogin(authentication);
            default -> throw new NoBugsException("Invalid social login type", HttpStatus.BAD_REQUEST);
        };
    }

    private SocialAuthToken googleLogin(SocialUserAuthenticationDTO authentication) {
        GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), JSON_FACTORY)
                .setAudience(Collections.singletonList(GOOGLE_CLIENT_ID))
                .build();
        try {
            return new GoogleAuthToken(verifier.verify(authentication.getSocialToken()));
        } catch (Exception e) {
            throw new NoBugsException(e.getMessage(), HttpStatus.UNAUTHORIZED);
        }
    }

    public SocialAuthToken facebookLogin(SocialUserAuthenticationDTO authentication) {
        try {
            String url = FACEBOOK_GRAPH_URL + authentication.getSocialToken();
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw  new NoBugsException("Failed to validate Facebook token", HttpStatus.valueOf(response.statusCode()));
            }

            JSONObject jsonObject = new JSONObject(response.body());

            return new FacebookAuthToken(jsonObject.getString("id"), jsonObject.getString("email"), jsonObject.getString("name"));
        } catch (Exception e) {
            assert e instanceof NoBugsException;
            throw new NoBugsException(e.getMessage(), ((NoBugsException)e).getHttpStatus() );
        }
    }
}