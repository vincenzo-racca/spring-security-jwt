package com.vincenzoracca.springsecurityjwt.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vincenzoracca.springsecurityjwt.model.entity.UserEntity;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.*;

import static com.vincenzoracca.springsecurityjwt.util.CustomSecurityHeaders.ACCESS_TOKEN;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class UserResourceTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private ObjectMapper objectMapper;


    @Test
    void findAllWithAuthToken() throws Exception {

        //test authentication and get JWT
        String jwt = authenticateAndRetrieveJWT("rossi", "1234");

        // Set the request headers with content type
        HttpHeaders headersUsers = new HttpHeaders();
        headersUsers.setBearerAuth(jwt);
        HttpEntity<String> requestUser = new HttpEntity<>(headersUsers);


        ResponseEntity<UserEntity[]> usersResponse = restTemplate.exchange(
                "http://localhost:" + port + "/api/users",
                HttpMethod.GET,
                requestUser,
                UserEntity[].class);

        assertThat(usersResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(usersResponse.getBody()).hasSize(2);

    }

    @Test
    void findAllWithoutAuthToken() {

        // Set the request headers with content type
        HttpHeaders headersUsers = new HttpHeaders();
        headersUsers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> requestUser = new HttpEntity<>(headersUsers);


        ResponseEntity<UserEntity[]> usersResponse = restTemplate.exchange(
                "http://localhost:" + port + "/api/users",
                HttpMethod.GET,
                requestUser,
                UserEntity[].class);

        assertThat(usersResponse.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

    }

    private String authenticateAndRetrieveJWT(String username, String password) throws JsonProcessingException {
        // Create the request body with username and password
        UserEntity loginRequest = new UserEntity();
        loginRequest.setUsername(username);
        loginRequest.setPassword(password);
        String requestBody = objectMapper.writeValueAsString(loginRequest);

        // Set the request headers with content type
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        // Create the HttpEntity with request body and headers
        HttpEntity<String> requestEntity = new HttpEntity<>(requestBody, headers);

        // Make the POST request to the login API with TestRestTemplate
        ResponseEntity<UserEntity> responseEntity = restTemplate.exchange(
                "http://localhost:" + port + "/api/login",
                HttpMethod.POST,
                requestEntity,
                UserEntity.class);

        assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);

        String jwt = responseEntity.getHeaders().get(ACCESS_TOKEN.getValue()).get(0);
        assertThat(jwt).isNotNull();

        return jwt;
    }

}
