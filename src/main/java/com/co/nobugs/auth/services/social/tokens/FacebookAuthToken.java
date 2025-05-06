package com.co.nobugs.auth.services.social.tokens;

import com.co.nobugs.auth.services.interfaces.SocialAuthToken;

import java.util.HashMap;
import java.util.Map;

public class FacebookAuthToken implements SocialAuthToken {
    private final String id;
    private final String email;
    private final String name;

    public FacebookAuthToken(String id, String email, String name) {
        this.id = id;
        this.email = email;
        this.name = name;
    }

    @Override
    public String getSubject() {
        return id;
    }

    @Override
    public Map<String, Object> getAttributes() {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", id);
        attributes.put("email", email);
        attributes.put("name", name);
        return attributes;
    }
}