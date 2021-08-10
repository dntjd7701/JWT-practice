package com.coven.jwt.config;

import com.coven.jwt.filter.MyFilter1;
import com.coven.jwt.jwt.JwtAuthenticationFilter;
import com.coven.jwt.jwt.JwtAuthorizationFilter;
import com.coven.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.web.filter.CorsFilter;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;
    private final UserRepository userRepository;

    @Bean // 해당 메서드의 리턴되는 값을 IoC로 등록해준다.
    public BCryptPasswordEncoder encodedPwd(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.addFilterBefore(new MyFilter1(), SecurityContextPersistenceFilter.class);
        http.csrf().disable();
        // Session 을 사용하지 않겠다. Stateless 서버로 만들겠다.
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(corsFilter) // corsFilter로 설정된 필터를 거쳐야 가능하다.
                // @CrossOrigin(인증 X), Filter(인증 O) - 시큐리티 필터에 등록 인증

                .formLogin().disable() // form 태그로 로그인하는것을 사용하지 않겠다.

                .httpBasic().disable() // 기본적인 http 방식도 사용하지 않겠다.
                .addFilter(new JwtAuthenticationFilter(authenticationManager())) //AuthenticationManager 인자로 꼭 던져줘야돼
                .addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository)) //AuthenticationManager 인자로 꼭 던져줘야돼
                // 위에는 jwt를 사용하기 위해선 고정적으로 사용한다.

                .authorizeRequests()
                .antMatchers("/api/vi/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/api/vi/manager/**")
                .access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/api/vi/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();


    }
}
