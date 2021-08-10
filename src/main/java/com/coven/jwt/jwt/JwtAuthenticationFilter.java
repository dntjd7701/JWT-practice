package com.coven.jwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.coven.jwt.auth.PrincipalDetails;
import com.coven.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter 가 있음.
// /login 요청해서 username, password를 post로 전송하면 이 필터가 동작한다.

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // 1. username, password 받기
        System.out.println("JwtAuthenticationFilter:로그인 시도 중..");
        try {
//            BufferedReader br = request.getReader();
//            String input = null;
//            while((input = br.readLine()) != null){
//                System.out.println(input);

//         json요청이라고 가정하고 parsing하기
            // json 형식 parsing해주는 object 사용하기
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);

            System.out.println(user);

            // 토큰 만들고 (받아온 정보로) 인증해보기
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // 로그인 시도하기
            // PrincipalDetailsService의 loadByUsername()가 실행이 된다. (username만 받고, password는 스프링이 알아서 처리해줌)
            // 정상이면 authentication이 리턴된다.
            // DB에 있는 username과 password가 일치한다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // authentication 객체가 session 영역에 저장된다. => 로그인 완료 ㅇㅇ
            PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
            System.out.println("로그인 완료됌?"+principalDetails.getUser().getUsername()); // 로그인이 정상적으로 이루어진것. (값이 있다면)
            // authentication object -> session saved
            // 권한 관리를 Spring Security 가 대신 해주기 때문에 편하게 하기 위해 return 해준다.
            // 굳이 JWT 토큰을 사용하면서 session 을 사용할 이유는 없다. 단지 권한 처리 때문에 session 에 넣어 주는것.
            return authentication;

        }catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
    //attemptAuthentication 실행 후 인증이 정상적으로 되었으면, successfulAuthentication 함수가 실행된다.
    // JWT 토큰을 만들어서 request 한 사용자에게 JWT 토큰을 response 해주면 된다.

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됌 : 인증이 완료되었다는 의미이다.");
        PrincipalDetails principalDetails = (PrincipalDetails)authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject("cos 토큰")
                .withExpiresAt(new Date(System.currentTimeMillis()+(60000*10)))
                // 만료시간
                .withClaim("id",principalDetails.getUser().getId()) // 내가 넣고 싶은 키 벨류 값, 막 넣어도됌
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));
        // signature
        // RSA(x), Hash 암호 방식임.
        // 특징으로 secret 값이 필요함. 여기선 "cos"
        // RSA는 공개, 비밀키 방식
        response.addHeader("Authorization","Bearer "+jwtToken);
    }
}


// 2. 정상적인 사용자인지 확인하기
// 3. authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출이된다.
// 4. 그럼 loadByUsername()이 실행이 된다.
// 5. PrincipalDetails 을 세션에 담고 - 권한 관리를 위해서
// 6. JWT 토큰을 만들어서 응답해주면된다.