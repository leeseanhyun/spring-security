package com.infovine.security;

import java.util.List;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class CustomAuthenticationProvider2 implements AuthenticationProvider {

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    String loginId = authentication.getName();
    String password = (String) authentication.getCredentials();

    // 아이디 검증
    // 패스워드 검증

    return new UsernamePasswordAuthenticationToken(loginId, password, List.of(new SimpleGrantedAuthority("ROLE_USER")));
  }

  @Override
  public boolean supports(Class<?> authentication) {
    // instanceof는 특정 Object가 어떤 클래스/인터페이스를 상속/구현했는지를 체크
    // Class.isAssignableFrom()은 특정 Class가 어떤 클래스/인터페이스를 상속/구현했는지 체크
    return authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
  }
}
