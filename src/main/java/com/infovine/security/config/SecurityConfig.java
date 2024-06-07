package com.infovine.security.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

  private static final String PASSWORD = "{noop}1111";
  private static final String ROLE_IS_USER = "USER";

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

    HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
    requestCache.setMatchingRequestParameterName("customParam=y");

    // Authentication : 인증에 성공한 정보
    http
        // http 인가 정책을 설정하겠다라는 의미
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/logoutSuccess").permitAll()
            .requestMatchers("/anonymous").hasRole("GUEST")
            .requestMatchers("/anonymousContext", "/authentication").permitAll()
            .anyRequest().authenticated()
        )
        .formLogin(form -> form
            .successHandler(new AuthenticationSuccessHandler() {
              @Override
              public void onAuthenticationSuccess(HttpServletRequest request,
                  HttpServletResponse response, Authentication authentication)
                  throws IOException, ServletException {
                SavedRequest savedRequest = requestCache.getRequest(request, response);
                String redirectUrl = savedRequest.getRedirectUrl();
                response.sendRedirect(redirectUrl);
              }
            })
        )
        .requestCache(cache -> cache.requestCache(requestCache))

        .logout(logout -> logout
            .logoutUrl("/logout")
            .logoutRequestMatcher(
                new AntPathRequestMatcher("/logout", "POST"))     // .logoutUrl보다 우선적으로 적용됨
            .logoutSuccessUrl("/logoutSuccess")
            .logoutSuccessHandler(new LogoutSuccessHandler() {
              @Override
              public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                  Authentication authentication) throws IOException, ServletException {
                response.sendRedirect("/logoutSuccess");
              }
            })
            .deleteCookies("JSESSIONID", "remember-me")
            .invalidateHttpSession(true)
            .clearAuthentication(true)
            .addLogoutHandler(new LogoutHandler() {
              @Override
              public void logout(HttpServletRequest request, HttpServletResponse response,
                  Authentication authentication) {
                HttpSession session = request.getSession();
                session.invalidate();   // 무효화
                SecurityContextHolder.getContextHolderStrategy().getContext()
                    .setAuthentication(null);   // ContextHolder에 있는 객체 삭제
                SecurityContextHolder.getContextHolderStrategy().clearContext();
              }
            })
            .permitAll()
        );
        /*
        .anonymous(anonymous -> anonymous
            .principal("geust")
            .authorities("ROLE_GUEST")
        )
        */
        /*
        .rememberMe(rememberMe -> rememberMe
                // true이면 무조건 Remember 쿠키 생성
//            .alwaysRemember(true)
                .tokenValiditySeconds(3600)
                .userDetailsService(userDetailsService())
                .rememberMeParameter("remember")
                .rememberMeCookieName("remember")
                .key("security")
        );
        */
        /*
        .formLogin(form -> form
//            .loginPage("/loginPage")
                .loginProcessingUrl("/loginProc")
                .defaultSuccessUrl("/")   //alwaysUse true 로그인 후 이동하는 고정페이지
                .failureUrl("/failed")
                .usernameParameter("userId")
                .passwordParameter("password")
                // 성공/실패 핸들러를 정의하면 핸들러가 우선순위
                .successHandler((request, response, authentication) -> {
                  System.out.println("authentication : " + authentication);
                  response.sendRedirect("/home");
                })
                .failureHandler((request, response, exception) -> {
                  System.out.println("exception : " + exception);
                  response.sendRedirect("/login");
                })
                .permitAll()
        );
        */

    return http.build();
  }

  // application.yml 중복 시 아래 코드가 우선순위임.
  @Bean
  public UserDetailsService userDetailsService() {
    UserDetails user = User.withUsername("user")
        .password(PASSWORD)
        .roles(ROLE_IS_USER).build();
//    UserDetails user2 = User.withUsername("user2")
//        .password(PASSWORD)
//        .roles(ROLE_IS_USER).build();
//    UserDetails user3 = User.withUsername("user3")
//        .password(PASSWORD)
//        .roles(ROLE_IS_USER).build();
//    return new InMemoryUserDetailsManager(user, user2, user3);
    return new InMemoryUserDetailsManager(user);
  }
}
