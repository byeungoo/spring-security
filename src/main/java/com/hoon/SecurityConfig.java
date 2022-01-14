package com.hoon;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity  // Security 관련된 설정 클래스 Import하는 어노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // 인가
        http.authorizeRequests()
                .anyRequest().authenticated();

        // 인증
        http.formLogin()
                .loginPage("/loginPage")
        .defaultSuccessUrl("/")
        .failureUrl("/login")
        .usernameParameter("userId")
        .passwordParameter("passwd")
        .loginProcessingUrl("/login_proc")
        .successHandler(new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                System.out.println("authentication : " + authentication.getName());
                response.sendRedirect("/");
            }
        })
        .failureHandler(new AuthenticationFailureHandler() {
            @Override
            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                System.out.println("exception : " + exception.getMessage());
                response.sendRedirect("/login");
            }
        })
        .permitAll() // 로그인 페이지의 경우는 인증을 받지 않아도 접근이 가능하도록 설정
        ;

    }

}
