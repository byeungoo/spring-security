package com.hoon;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity  // Security 관련된 설정 클래스 Import하는 어노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // 인가
        http.authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                // access :  주어진 SpEL 표현식의 평가 결과가 true이면 접근을 허용
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated()
        ;

        // 인증
        http.formLogin()
                //.loginPage("/loginPage")
        .defaultSuccessUrl("/")
        .failureUrl("/login")
        .usernameParameter("userId")
        .passwordParameter("passwd")
        .loginProcessingUrl("/login_proc")
        .successHandler(new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                System.out.println("authentication : " + authentication.getName());
                RequestCache requestCache = new HttpSessionRequestCache();  // 인증 실패했을 때 요청이 여기 저장되는데 인증하고나서 여기로 가게한다.
                SavedRequest savedRequest = requestCache.getRequest(request, response);
                String redirectUrl = savedRequest.getRedirectUrl();
                response.sendRedirect(redirectUrl);

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

        http.logout()   // 기본적으로는 post  방식임
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me")   // 서버에서 만든 쿠키 삭제하고 싶을 때 사용
        .and()
                .rememberMe()
                .rememberMeParameter("remember")    // 기본값은 remember-me
                .tokenValiditySeconds(3600) // 기본 값은 2주
                .userDetailsService(userDetailsService)
        ;

        http.sessionManagement()
                .maximumSessions(1)
                .maxSessionsPreventsLogin(true) // true : 로그인 후 하나 더 로그인하면 뒤에 로그인은 세션 초과라 로그인 불가.
                                                // false : 로그인 후 하나 더 로그인하면 기존에 로그인했던거는 만료처리함. default는 false
        ;

        http.sessionManagement()
                .sessionFixation().changeSessionId()    // 기본값
        ;

        http.exceptionHandling()
                .authenticationEntryPoint(new AuthenticationEntryPoint() {
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })  // 인증 실패 시 처리
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied");
                    }
                }) // 인가 실패 시 처리
        ;

        http.csrf().disable();   // CSRF(Cross-Site Request Forgery) disable처리. 기본적으로 활성화되있긴함. 개발할 때 켜놓고하는게 좋다.

    }

    /**
     * 사용자 생성 및 권한 설정
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");    // {noop}은 암호화 안한다고 설정.
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");
    }
}
