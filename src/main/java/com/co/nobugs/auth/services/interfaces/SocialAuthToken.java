package com.co.nobugs.auth.services.interfaces;

import java.util.Map;

public interface SocialAuthToken {
    String getSubject();
    Map<String, Object> getAttributes();
}