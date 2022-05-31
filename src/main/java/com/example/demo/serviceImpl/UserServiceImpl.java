package com.example.demo.serviceImpl;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.AdminUpdateUserAttributesRequest;
import com.amazonaws.services.cognitoidp.model.AttributeType;
import com.amazonaws.services.cognitoidp.model.AuthFlowType;
import com.amazonaws.services.cognitoidp.model.AuthenticationResultType;
import com.amazonaws.services.cognitoidp.model.ConfirmForgotPasswordRequest;
import com.amazonaws.services.cognitoidp.model.ConfirmForgotPasswordResult;
import com.amazonaws.services.cognitoidp.model.ConfirmSignUpRequest;
import com.amazonaws.services.cognitoidp.model.ConfirmSignUpResult;
import com.amazonaws.services.cognitoidp.model.ForgotPasswordRequest;
import com.amazonaws.services.cognitoidp.model.ForgotPasswordResult;
import com.amazonaws.services.cognitoidp.model.SignUpRequest;
import com.amazonaws.services.cognitoidp.model.SignUpResult;
import com.amazonaws.util.Base64;
import com.example.demo.configuration.CommonConfiguration;
import com.example.demo.configuration.cognitoConfiguration;
import com.example.demo.dto.UserSignUpRequest;
import com.example.demo.dto.UserToken;
import com.example.demo.service.UserService;


@Service
public class UserServiceImpl implements UserService {

	@Autowired
	private CommonConfiguration commonConfiguration;
	
	@Autowired
	private cognitoConfiguration cognitoConfiguration;
	
	private static final String ALGORITHM = "HmacSHA256";
	
	Function<String,String> prepareUserName = s -> {
		s.replace(".", "");
		return s.substring(0,s.indexOf("@"));
	};
	
	@Override
	public void registerUser(UserSignUpRequest userSignUpRequest) throws InvalidKeyException, NoSuchAlgorithmException {
		SignUpResult signUpResult = null;
		String mobileNo = userSignUpRequest.getPhoneNumber();
		userSignUpRequest.setPhoneNumber("+91" + mobileNo);
		String userName = prepareUserName.apply(userSignUpRequest.getEmail());
		SignUpRequest signUpRequest = prepareSignUpRequest(userSignUpRequest,userName);
		try {
			signUpResult = cognitoConfiguration.getAmazonCognitoIdentityClient().signUp(signUpRequest);
		}
		catch(Exception e) {
			System.out.println(e.getMessage());
			System.out.println("failed signUp");
		}
		VerifyEmailAndPhoneNumber(userName);
	}

	private void VerifyEmailAndPhoneNumber(String userName) {
		AdminUpdateUserAttributesRequest adminUpdateUserAttribute = new AdminUpdateUserAttributesRequest();
		adminUpdateUserAttribute.setUsername(userName);
		adminUpdateUserAttribute.setUserPoolId(commonConfiguration.getUserPoolId());
		
		List<AttributeType> list = new ArrayList<>();
		
		AttributeType phoneNoVerified = new AttributeType();
		phoneNoVerified.setName("phone_number_verified");
		phoneNoVerified.setValue("TRUE");
		list.add(phoneNoVerified);
		
		AttributeType emailVerified = new AttributeType();
		emailVerified.setName("email_verified");
		emailVerified.setValue("TRUE");
		list.add(emailVerified);
		
		adminUpdateUserAttribute.setUserAttributes(list);
		cognitoConfiguration.getAmazonCognitoIdentityClient().adminUpdateUserAttributes(adminUpdateUserAttribute);
	}

	private SignUpRequest prepareSignUpRequest(UserSignUpRequest userSignUpRequest,String userName) throws InvalidKeyException, NoSuchAlgorithmException {
		SignUpRequest SignUpRequest = new SignUpRequest();
		SignUpRequest.setClientId(commonConfiguration.getCognitoClientId());
		SignUpRequest.setPassword(userSignUpRequest.getPassword());
		SignUpRequest.setUsername(userName);
		
		List<AttributeType> attributes = new ArrayList<>();
		
		AttributeType phoneNumber = new AttributeType();
		phoneNumber.setName("phone_number");
		phoneNumber.setValue(userSignUpRequest.getPhoneNumber());
		attributes.add(phoneNumber);
		
		AttributeType email = new AttributeType();
		email.setName("email");
		email.setValue(userSignUpRequest.getEmail());
		attributes.add(email);
		
		AttributeType gender = new AttributeType();
		gender.setName("gender");
		gender.setValue("M");
		attributes.add(gender);
		
		AttributeType address = new AttributeType();
		address.setName("address");
		address.setValue("Noida");
		attributes.add(address);
		
		AttributeType dateOfBirth = new AttributeType();
		dateOfBirth.setName("birthdate");
		dateOfBirth.setValue(userSignUpRequest.getDateOfBirth());
		attributes.add(dateOfBirth);
		
		AttributeType name = new AttributeType();
		name.setName("name");
		name.setValue(userSignUpRequest.getName());
		attributes.add(name);
		System.out.println(attributes);
		SignUpRequest.setUserAttributes(attributes);
		
		SignUpRequest.setSecretHash(getSecretHash(userName,commonConfiguration.getCognitoClientId(),commonConfiguration.getCognitoClientSecretKey()));	
		return SignUpRequest;
	}
	
	private String getSecretHash(String username, String clientAppId, String clientAppSecret)
			throws InvalidKeyException, NoSuchAlgorithmException {
		byte[] data = (username + clientAppId).getBytes(StandardCharsets.UTF_8);
		byte[] key = clientAppSecret.getBytes(StandardCharsets.UTF_8);

		return Base64.encodeAsString(hmacSHA256(data, key));
	}

	static byte[] hmacSHA256(byte[] data, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
		Mac mac = Mac.getInstance(ALGORITHM);
		mac.init(new SecretKeySpec(key, ALGORITHM));
		return mac.doFinal(data);
	}

	@Override
	public void confirmSignUp(String email, String otp) throws InvalidKeyException, NoSuchAlgorithmException {
		String userName = prepareUserName.apply(email);
		ConfirmSignUpRequest confirmSignUpRequest = otpVerification(userName,otp);
		ConfirmSignUpResult confirmSignUpResult=cognitoConfiguration.getAmazonCognitoIdentityClient().confirmSignUp(confirmSignUpRequest);
		System.out.println(confirmSignUpResult);
	}

	private ConfirmSignUpRequest otpVerification(String userName, String otp) throws InvalidKeyException, NoSuchAlgorithmException {
		ConfirmSignUpRequest signUpRequest = new ConfirmSignUpRequest();
		signUpRequest.setClientId(commonConfiguration.getCognitoClientId());
		signUpRequest.setUsername(userName);
		signUpRequest.setSecretHash(getSecretHash(userName, commonConfiguration.getCognitoClientId(), commonConfiguration.getCognitoClientSecretKey()));
		signUpRequest.setConfirmationCode(otp);
		return signUpRequest;
	}

	@Override
	public void requestPasswordChange(String email) throws InvalidKeyException, NoSuchAlgorithmException {
		String userName = prepareUserName.apply(email);
		ForgotPasswordRequest forgotPasswordRequest = prepareForgotPasswordRequest(userName);
		ForgotPasswordResult forgotPasswordResult = cognitoConfiguration.getAmazonCognitoIdentityClient().forgotPassword(forgotPasswordRequest);
		System.out.println(forgotPasswordResult);
	}

	private ForgotPasswordRequest prepareForgotPasswordRequest(String userName) throws InvalidKeyException, NoSuchAlgorithmException {
		ForgotPasswordRequest forgotPasswordRequest = new ForgotPasswordRequest();
		forgotPasswordRequest.setUsername(userName);
		forgotPasswordRequest.setClientId(commonConfiguration.getCognitoClientId());
		forgotPasswordRequest.setSecretHash(getSecretHash(userName, commonConfiguration.getCognitoClientId(), commonConfiguration.getCognitoClientSecretKey()));
		return forgotPasswordRequest;
	}

	@Override
	public void resetPassword(String email,String otp,String newPassword) throws InvalidKeyException, NoSuchAlgorithmException {
		String userName = prepareUserName.apply(email);
		ConfirmForgotPasswordRequest confirmForgotPasswordRequest = prepareResetPassword(userName,otp,newPassword);
		ConfirmForgotPasswordResult confirmForgotPasswordResult = cognitoConfiguration.getAmazonCognitoIdentityClient().confirmForgotPassword(confirmForgotPasswordRequest);
		System.out.println(confirmForgotPasswordResult);
	}

	private ConfirmForgotPasswordRequest prepareResetPassword(String userName, String otp,String newPassword) throws InvalidKeyException, NoSuchAlgorithmException {
		ConfirmForgotPasswordRequest confirmForgotPasswordRequest = new ConfirmForgotPasswordRequest();
		confirmForgotPasswordRequest.setClientId(commonConfiguration.getCognitoClientId());
		confirmForgotPasswordRequest.setUsername(userName);
		confirmForgotPasswordRequest.setConfirmationCode(otp);
		confirmForgotPasswordRequest.setPassword(newPassword);
		confirmForgotPasswordRequest.setSecretHash(getSecretHash(userName, commonConfiguration.getCognitoClientId(), commonConfiguration.getCognitoClientSecretKey()));
		return confirmForgotPasswordRequest;
	}
	
	@Override
	public UserToken signIn(String email,String password) throws InvalidKeyException, NoSuchAlgorithmException {
		String userName = prepareUserName.apply(email);
	    AuthenticationResultType authenticationResult = null;
	    Map<String,String> requestParams = new HashMap<>();
	    requestParams.put("USERNAME", userName);
	    requestParams.put("PASSWORD", password);
	    requestParams.put("SECRET_HASH", getSecretHash(userName, commonConfiguration.getCognitoClientId(), commonConfiguration.getCognitoClientSecretKey())); 
	    UserToken userToken = new UserToken();
	    final AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest();
	       authRequest.withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
	       .withClientId(commonConfiguration.getCognitoClientId())
	       .withUserPoolId(commonConfiguration.getUserPoolId())
	       .withAuthParameters(requestParams);
	       AdminInitiateAuthResult adminInitiateAuthResult = cognitoConfiguration.getAmazonCognitoIdentityClient().adminInitiateAuth(authRequest);
	    if(null == adminInitiateAuthResult) {
	    	System.out.println("Error in refershToken");
	    }
	    else {
	    	userToken.setAccessToken(adminInitiateAuthResult.getAuthenticationResult().getAccessToken());
	    	userToken.setIdToken(adminInitiateAuthResult.getAuthenticationResult().getIdToken());
	    	userToken.setRefreshToken(adminInitiateAuthResult.getAuthenticationResult().getRefreshToken());
	    }
	    return userToken;
	}
	
}
