package com.infovine.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class SecurityContextService {

  public void securityContext() {
    SecurityContext securitycontext = SecurityContextHolder.getContextHolderStrategy().getContext();
    Authentication auth = securitycontext.getAuthentication();
    System.out.println("authentication = " + auth);
  }

}
