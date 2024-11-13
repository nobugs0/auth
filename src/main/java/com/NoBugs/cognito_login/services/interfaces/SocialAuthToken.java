package com.NoBugs.cognito_login.services.interfaces;

import java.util.Map;

public interface SocialAuthToken {
    String getSubject();
    Map<String, Object> getAttributes();
}