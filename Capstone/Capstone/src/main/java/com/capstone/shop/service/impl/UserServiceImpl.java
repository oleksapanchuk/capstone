package com.capstone.shop.service.impl;

import com.capstone.shop.entity.LoginProvider;
import com.capstone.shop.entity.Role;
import com.capstone.shop.entity.User;
import com.capstone.shop.repository.UserRepository;
import com.capstone.shop.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
@RequiredArgsConstructor
@Log4j2
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    @Override
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    @Override
    public OAuth2UserService<OidcUserRequest, OidcUser> oidcLoginHandler() {
        return userRequest -> {
            LoginProvider loginProvider = getProvider(userRequest);

            OidcUser oidcUser = new OidcUserService().loadUser(userRequest);
            log.info("google userRequest: {}", oidcUser);
            return User
                    .builder()
                    .name(oidcUser.getAttribute("name"))
                    .username(oidcUser.getEmail())
                    .email(oidcUser.getEmail())
                    .imageUrl(oidcUser.getPicture())
                    .role(Role.ROLE_USER)
                    .provider(loginProvider)
                    .isEmailVerified(oidcUser.getEmailVerified())
                    .build();
        };
    }

    @Override
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2LoginHandler() {
        return userRequest -> {
            LoginProvider loginProvider = getProvider(userRequest);

            OAuth2User oAuth2User = new DefaultOAuth2UserService().loadUser(userRequest);
            log.info("github userRequest: {}", oAuth2User);
            return User
                    .builder()
                    .name(oAuth2User.getAttribute("name"))
                    .username(oAuth2User.getAttribute("login"))
                    .email(oAuth2User.getAttribute("email"))
                    .imageUrl(oAuth2User.getAttribute("avatar_url"))
                    .role(Role.ROLE_USER)
                    .provider(loginProvider)
                    .build();
        };
    }


    private LoginProvider getProvider(OAuth2UserRequest userRequest) {
        return LoginProvider.valueOf(userRequest.getClientRegistration().getRegistrationId().toUpperCase());
    }

}
