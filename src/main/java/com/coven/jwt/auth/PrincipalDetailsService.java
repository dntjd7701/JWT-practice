package com.coven.jwt.auth;

import com.coven.jwt.model.User;
import com.coven.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// http://localhost:8080/login -> 동작을 하지 않는다.
// 직접 요놈을 때려주는 필터가 필요함.
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailsService의 실행 확인 ");
        User userEntity = userRepository.findByUsername(username);
        System.out.println(userEntity);
        return new PrincipalDetails(userEntity);
    }
}
