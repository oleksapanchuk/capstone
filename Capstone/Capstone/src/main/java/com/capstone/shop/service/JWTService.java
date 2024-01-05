package com.capstone.shop.service;

import com.capstone.shop.entity.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.HashMap;

public interface JWTService {
    String generateToken(UserDetails userDetails);
    String generateRefreshToken(HashMap<String, Object> extraClaims, UserDetails userDetails);
    String extractUsername(String token);
    boolean isTokenValid(String token, UserDetails userDetails);


}
