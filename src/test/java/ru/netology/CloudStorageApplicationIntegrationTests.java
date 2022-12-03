package ru.netology;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import ru.netology.dto.AuthenticationRequest;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class CloudStorageApplicationIntegrationTests {
    @Autowired
    private MockMvc mvc;
    @Autowired
    private ObjectMapper objectMapper;
    private final String LOGIN_PATH = "/login";
    private final String LOGOUT_PATH = "/logout";
    private final String LOGIN = "user";
    private final String BAD_LOGIN = "bad login";
    private final String PASSWORD = "password";

    @Test
    void loginUserUnauthenticated() throws Exception {
        AuthenticationRequest authenticationRequest = new AuthenticationRequest(BAD_LOGIN, PASSWORD);
        mvc.perform(post(LOGIN_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authenticationRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void loginUserAuthenticated() throws Exception {
        AuthenticationRequest authenticationRequest = new AuthenticationRequest(LOGIN, PASSWORD);
        mvc.perform(post(LOGIN_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authenticationRequest)))
                .andExpect(status().isOk());
    }

    @Test
    void logoutUserTest() throws Exception {
        AuthenticationRequest authenticationRequest = new AuthenticationRequest(LOGIN, PASSWORD);
        mvc.perform(post(LOGOUT_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authenticationRequest)))
                .andExpect(status().is3xxRedirection());
    }
}