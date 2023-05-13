package com.vincenzoracca.springsecurityjwt.api;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.vincenzoracca.springsecurityjwt.model.dto.RoleDTO;
import com.vincenzoracca.springsecurityjwt.model.entity.UserEntity;
import com.vincenzoracca.springsecurityjwt.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;


@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
@Slf4j
public class UserResource {


    private final UserService userService;

    @GetMapping
    public ResponseEntity<List<UserEntity>> findAll() {
        return ResponseEntity.ok().body(userService.findAll());
    }

    @GetMapping("/{username}")
    public ResponseEntity<UserEntity> findByUsername(@PathVariable String username) {
        return ResponseEntity.ok().body(userService.findByUsername(username));
    }

    @PostMapping
    public ResponseEntity<UserEntity> save(@RequestBody UserEntity user) {
        UserEntity userEntity = userService.save(user);
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentRequest().path("/{username}")
                .buildAndExpand(userEntity.getUsername()).toUriString());
        return ResponseEntity.created(uri).build();
    }


    @PostMapping("/{username}/addRoleToUser")
    public ResponseEntity<?> addRoleToUser(@PathVariable String username, @RequestBody RoleDTO request) {
        UserEntity userEntity = userService.addRoleToUser(username, request.getRoleName());
        return ResponseEntity.ok(userEntity);
    }

    @GetMapping("/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
           try {
               Map<String, String> tokenMap = userService.refreshToken(authorizationHeader, request.getRequestURL().toString());
               response.addHeader("access_token", tokenMap.get("access_token"));
               response.addHeader("refresh_token", tokenMap.get("refresh_token"));
           }
           catch (Exception e) {
               log.error(String.format("Error refresh token: %s", authorizationHeader), e);
               response.setStatus(FORBIDDEN.value());
               Map<String, String> error = new HashMap<>();
               error.put("errorMessage", e.getMessage());
               response.setContentType(APPLICATION_JSON_VALUE);
               new ObjectMapper().writeValue(response.getOutputStream(), error);
           }
        } else {
            throw new RuntimeException("Refresh token is missing");
        }
    }
}
