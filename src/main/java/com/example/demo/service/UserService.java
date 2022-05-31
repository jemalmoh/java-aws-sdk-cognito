package com.example.demo.service;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import org.springframework.stereotype.Service;

import com.example.demo.dto.UserSignUpRequest;
import com.example.demo.dto.UserToken;

@Service
public interface UserService {

	public void registerUser(UserSignUpRequest userSignUpRequest) throws InvalidKeyException, NoSuchAlgorithmException;

	public void confirmSignUp(String email, String otp) throws InvalidKeyException, NoSuchAlgorithmException;

	public void requestPasswordChange(String email) throws InvalidKeyException, NoSuchAlgorithmException;

	public void resetPassword(String email,String otp,String newPassword) throws InvalidKeyException, NoSuchAlgorithmException;

	public UserToken signIn(String email,String password) throws InvalidKeyException, NoSuchAlgorithmException;

}
