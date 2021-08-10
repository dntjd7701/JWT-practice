package com.coven.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter1 implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        // 토큰 : cos 이걸 만들어줘야됌
        // id, pw 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어줘야된다.그리고 그걸 응답을 해준다.
        // 그럼 요청할 때 마다 header에 Authorization으로 value에 토큰을 가지고 온다
        // 그때 토큰이 넘어오면, 이 토큰이 내가 만든 토큰이 맞는지만 검증하면 된다.
        // -> RSA, HS256
        if(request.getMethod().equals("POST")) {
            String headerAuth = request.getHeader("Authorization");
            System.out.println(headerAuth);

            if (headerAuth.equals("cos")) {
                filterChain.doFilter(request, response);
            } else {
                PrintWriter out = response.getWriter();
                out.println("인증안됌");
            }
        }

    }
}
