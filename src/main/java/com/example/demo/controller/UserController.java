package com.example.demo.controller;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.dto.UserSignUpRequest;
import com.example.demo.dto.UserToken;
import com.example.demo.service.UserService;

@RestController
@CrossOrigin
@RequestMapping("/user")
public class UserController {

	@Autowired
	private UserService userService;
	
	@PostMapping(value="/register")
	public ResponseEntity<String> registerUser(@RequestBody UserSignUpRequest userSignUpRequest) throws InvalidKeyException, NoSuchAlgorithmException{
		userService.registerUser(userSignUpRequest);
		return new ResponseEntity<>("Success",HttpStatus.OK);
	}

	@PostMapping(value="/verifyOtp")
	public ResponseEntity<String> confirmSignUp(@RequestParam("email") String email,@RequestParam("otp") String otp) throws InvalidKeyException, NoSuchAlgorithmException{
		userService.confirmSignUp(email,otp);
		return new ResponseEntity<>("Success",HttpStatus.OK);
	}
	
	@PostMapping(value="request/resetPassword")
	public ResponseEntity<String> requestPasswordChange(@RequestParam("email") String email) throws InvalidKeyException, NoSuchAlgorithmException{
		userService.requestPasswordChange(email);
		return new ResponseEntity<>("Success",HttpStatus.OK);
	}
	
	@PostMapping(value="/resetPassword")
	public ResponseEntity<String> resetPassword(@RequestParam("email") String email,@RequestParam("otp") String otp,@RequestParam("newPassword") String newPassword) throws InvalidKeyException, NoSuchAlgorithmException{
		userService.resetPassword(email,otp,newPassword);
		return new ResponseEntity<>("Success",HttpStatus.OK);
	}
	
	@PostMapping(value="/login")
	public ResponseEntity<UserToken> loginUser(@RequestParam("email") String email,@RequestParam("password") String password) throws InvalidKeyException, NoSuchAlgorithmException{
		UserToken userToken = userService.signIn(email, password);
		return new ResponseEntity<>(userToken,HttpStatus.OK);
	}
}
