package com.coven.jwt.jwt;


// 시큐리티가 filter를 가지고 있는데, 그 filter 중 BasicAuthenticationFilter 라는게 있다.
// 권한이나 인증이 필요한 특정 주소를 요청했을 때, 이 필터를 무조권 타게 되어있다.

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.coven.jwt.auth.PrincipalDetails;
import com.coven.jwt.model.User;
import com.coven.jwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    // 인증이나 권한이 필요한 요청이 있을 때 이 메소드를 타게 된다.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
//        super.doFilterInternal(request, response, chain);
        System.out.println("인증이나 권한이 필요한 주소 요청이 됌");
        String jwtHeader = request.getHeader("Authorization");
        System.out.println("==============" + jwtHeader);


        // header 가 정상적인지 확인
        if(jwtHeader == null || !jwtHeader.startsWith("Bearer ")){
            chain.doFilter(request, response);
            return;
        }

        // JWT 토큰 검증을 해서 정상적인 사용자인지 확인하기
        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
        String username = JWT.require(Algorithm.HMAC512("cos")).build().verify(jwtToken).getClaim("username").asString();

        // 서명이 정상적으로 됌.
        if(username != null){
            User userEntity = userRepository.findByUsername(username);
//             System.out.println(userEntity.getUsername());
            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
            // 로그인을 하지않고 정상적인 토큰을 가지고 있다면 강제로 인증을 시켜버린다.
            // user, password, 권한
            // 정상적인 로그인 요청이 아닌, JWT 토큰 서명을 통해서 정상이면 Authentication 객체를 만들어준다.
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            // 만든 객체를 Security session에 넣어서 인증한다.
            // SecurityContextHolder.getContext()
            // 강제로 Security session 에 접근하여 Authentication 저장, -> 강제 로그인
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request,response);
        }

    }
}
