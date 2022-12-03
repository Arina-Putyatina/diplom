package ru.netology.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import ru.netology.dto.AuthenticationRequest;
import ru.netology.security.JwtTokenUtils;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
public class AuthenticationServiceTest {
    @InjectMocks
    private AuthenticationService authenticationService;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private JwtTokenUtils jwtTokenUtils;
    private final String USERNAME = "admin";
    private final String PASSWORD = "admin";
    private final UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(USERNAME, PASSWORD);
    private final String token = UUID.randomUUID().toString();
    private final AuthenticationRequest authenticationRequest = new AuthenticationRequest(USERNAME, PASSWORD);

    @Test
    void loginUserTest() {
        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        given(jwtTokenUtils.generateToken(authentication)).willReturn(token);
        assertEquals(token, authenticationService.loginUser(authenticationRequest));
    }
}