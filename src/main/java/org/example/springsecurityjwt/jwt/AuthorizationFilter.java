package org.example.springsecurityjwt.jwt;

import com.auth0.jwt.JWT;
import org.example.springsecurityjwt.model.User;
import org.example.springsecurityjwt.repository.UserRepository;
import org.example.springsecurityjwt.security.AppUserDetails;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;

public class AuthorizationFilter extends BasicAuthenticationFilter {

    private final UserRepository userRepository;

    public AuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        String header = request.getHeader(JwtProperties.HEADER);

        if (header == null || !header.startsWith(JwtProperties.PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        Authentication authentication = getUsernamePasswordAuthentication(request);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        chain.doFilter(request, response);
    }

    private Authentication getUsernamePasswordAuthentication(HttpServletRequest request) {

        String token = request.getHeader(JwtProperties.HEADER)
                .replace(JwtProperties.PREFIX,"");

        String userName = JWT.require(HMAC512(JwtProperties.SECRET.getBytes()))
                .build()
                .verify(token)
                .getSubject();

        if (userName != null) {
            User user = userRepository.findUserByUsername(userName);
            AppUserDetails principal = new AppUserDetails(user);
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userName, null, principal.getAuthorities());
            return authentication;
        }

        return null;
    }
}
