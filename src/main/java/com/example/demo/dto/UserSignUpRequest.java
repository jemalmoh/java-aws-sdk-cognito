package com.example.demo.dto;

import org.springframework.stereotype.Component;

import lombok.Data;

@Component
@Data
public class UserSignUpRequest {

	private String name;
	private String password;
	private String email;
	private String phoneNumber;
	private String dateOfBirth;
}
