package com.capstone.shop.dto;

import lombok.Data;
import lombok.experimental.SuperBuilder;

@Data
public class SignInRequest {
    private String email;
    private String password;
}
