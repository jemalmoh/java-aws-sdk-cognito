package com.example.demo.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;

import lombok.Data;

@Configuration
@Data
public class cognitoConfiguration {

	@Autowired
	private CommonConfiguration commonConfiguration;
	
	public AWSCognitoIdentityProvider getAmazonCognitoIdentityClient() {
		BasicAWSCredentials creds = new BasicAWSCredentials(commonConfiguration.getAccessKey(),commonConfiguration.getSecretKey());
        return AWSCognitoIdentityProviderClientBuilder.standard()
        		.withCredentials(new AWSStaticCredentialsProvider(creds))
        		.withRegion(commonConfiguration.getRegion())
        		.build();
	}
}
