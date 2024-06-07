package com.infovine.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

public class CustomAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

  public CustomAuthenticationFilter(HttpSecurity http) {
    super(new AntPathRequestMatcher("/api/login", "GET"));
    setSecurityContextRepository(getSecurityContextRepository(http));
  }

  private SecurityContextRepository getSecurityContextRepository(HttpSecurity http) {
    SecurityContextRepository securityContextRepository = http.getSharedObject(SecurityContextRepository.class);
    if (securityContextRepository == null) {
      securityContextRepository = new DelegatingSecurityContextRepository(
          new RequestAttributeSecurityContextRepository(),
          new HttpSessionSecurityContextRepository());
    }
    return securityContextRepository;
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
    String username = request.getParameter("username");
    String password = request.getParameter("password");

    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);

    return this.getAuthenticationManager().authenticate(token);
  }
}
