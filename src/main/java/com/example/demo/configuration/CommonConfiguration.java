package com.example.demo.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Configuration
@Data
public class CommonConfiguration {

	@Value("${cognito.client.id}")
	private String cognitoClientId;
	
    @Value("${aws.region}")
    private String region;
    
    @Value("${aws.access.key}")
	private String accessKey;

	@Value("${aws.secret.key}")
	private String secretKey;
	
	@Value("${cognito.client.secret}")
	private String cognitoClientSecretKey;
	
	@Value("${cognito.user.poolid}")
	private String userPoolId;

}
