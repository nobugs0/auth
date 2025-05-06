package com.co.nobugs.auth.config.amazon;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;

@Configuration
@RequiredArgsConstructor
public class AWSCognitoConfig {

    private final AwsCredentialsProvider awsCredentialsProvider;

    @Value("${aws.region}")
    private String awsRegion;

    @Bean
    public CognitoIdentityProviderClient cognitoIdentityProviderClient() {
        return CognitoIdentityProviderClient.builder()
                .credentialsProvider(awsCredentialsProvider)
                .region(Region.of(awsRegion))
                .build();
    }
}