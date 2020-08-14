package org.example.springsecurityjwt.jwt;

import com.auth0.jwt.JWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.springsecurityjwt.model.Login;
import org.example.springsecurityjwt.security.AppUserDetails;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;

public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public AuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        Login credentials = null;
        try {
            credentials = new ObjectMapper().readValue(request.getInputStream(), Login.class);
        } catch (IOException e) {
            e.printStackTrace();
        }

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                credentials.getUsername(),
                credentials.getPassword(),
                new ArrayList<>());

        Authentication authenticate = authenticationManager.authenticate(authenticationToken);

        return authenticate;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        AppUserDetails appUserDetails = (AppUserDetails) authResult.getPrincipal();

        String token = JWT.create()
                .withSubject(appUserDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .sign(HMAC512(JwtProperties.SECRET.getBytes()));

        response.addHeader(JwtProperties.HEADER, JwtProperties.PREFIX +  token);
    }
}
