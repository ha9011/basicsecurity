package io.security.basicsecurity;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.servlet.configuration.WebMvcSecurityConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@Configuration// 설정 파일이니깐
@EnableWebSecurity
public class SecurityConfig {

    /*
     * 스프링이 버전업 되면서 자연스럽게
     * WebSecurityConfigurerAdapter가 deprecate가 되었습니다.
     *
     * @Override
     * protected void configure(HttpSecurity http) throws Exception{
     * http
     *  .authorizeRequests().anyRequest().authenticated();
     *
     * http
     *  .formLogin();
     *
     * }
     *
     * 방식이 사라짐...
     */

    // 따라서 현재 @Bean 방식으로 등록되는 방식을 추천하고 있음
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests((authorize)->{
//            authorize.an
//        })

        http.authorizeHttpRequests()
                .anyRequest()// 어떤 요청이든간에든
                .authenticated(); // 인증을 받아야한다.

        // http.formLogin() -> 로그인 인증 기능이 작동함
        http.formLogin()
                //.loginPage("/loginPage") // 사용자 정의 로그인 페이지
                .defaultSuccessUrl("/") // 로그인 성공 후 이동 페이지
                .failureUrl("/login") // 로그인 실패 후 이동페이지
                .usernameParameter("userId") // 아이디 파라미터명 설정 ex) neme = "username" input
                .passwordParameter("passwd") // 패스워드 파라미터명 설정
                .loginProcessingUrl("/login_proc") // 로그인 fomr action url action = "/login" // ** 이 action값을 통해 usernamePasswdAuthenticationFilter가 실행됨 (4강 참고)
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        //authentication 인증 성공시 넘어 오는 데이터
//                        System.out.println("authentication : " + authentication.getName());
//                        response.sendRedirect("/");
//                    }
//                }) //로그인 성공 후 핸들러 호출
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                        System.out.println("exception " + exception.getMessage());
//                        response.sendRedirect("/login");
//                    }
//                }) //로그인 실패 후 핸들러
                .permitAll(); // loginPage 기재된 페이지를 모두 허락한다. 인가쪽에 anyRequest().auth...()가 있지만 예외처리라고 볼수있다.

        return http.build();
    }
}