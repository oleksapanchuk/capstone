package com.capstone.shop.service;

import com.capstone.shop.dto.JwtAuthenticationResponse;
import com.capstone.shop.dto.RefreshTokenRequest;
import com.capstone.shop.dto.SignInRequest;
import com.capstone.shop.dto.SignUpRequest;
import com.capstone.shop.entity.User;

public interface AuthenticationService {
    User signUp(SignUpRequest signUpRequest);

    JwtAuthenticationResponse signIn(SignInRequest signInRequest);

    JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
}
