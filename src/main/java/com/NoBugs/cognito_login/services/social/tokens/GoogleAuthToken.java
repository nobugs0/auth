package com.NoBugs.cognito_login.services.social.tokens;

import com.NoBugs.cognito_login.services.interfaces.SocialAuthToken;
import com.google.api.client.auth.openidconnect.IdToken;

import java.util.HashMap;
import java.util.Map;

public class GoogleAuthToken implements SocialAuthToken {
    private final IdToken idToken;

    public GoogleAuthToken(IdToken idToken) {
        this.idToken = idToken;
    }

    @Override
    public String getSubject() {
        return idToken.getPayload().getSubject();
    }

    @Override
    public Map<String, Object> getAttributes() {
        Map<String, Object> attributes = new HashMap<>();

        IdToken.Payload payload = idToken.getPayload();

        attributes.put("sub", payload.getSubject());
        attributes.put("email", payload.get("email"));
        attributes.put("name", payload.get("name"));
        attributes.put("phone", payload.get("phone_number"));
        return attributes;
    }
}