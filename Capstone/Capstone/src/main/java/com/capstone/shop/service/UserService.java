package com.capstone.shop.service;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

public interface UserService {

    UserDetailsService userDetailsService();
    OAuth2UserService<OidcUserRequest, OidcUser> oidcLoginHandler();
    OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2LoginHandler();
}
