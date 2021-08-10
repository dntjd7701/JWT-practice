package com.coven.jwt.controller;


import com.coven.jwt.model.User;
import com.coven.jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
public class RestApiController {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;



    @GetMapping("/home")
    public @ResponseBody String home(){
        return "<h1>Home<h1>";
    }


    @PostMapping ("/token")
    public @ResponseBody String token(){
        return "<h1>token<h1>";
    }

    @PostMapping("/join")
    public String join(@RequestBody User user){
        user.setRoles("ROLE_USER");

        // Security 암호화 (비밀번호)
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);

        // 회원가입은 잘되지만, 시큐리티 로그인이 안된다. -> 비밀번호가 암호화가 안되어있기 때문에. 위의 과정 필요
        userRepository.save(user);
        return "redirect:/home";
    }

    @GetMapping("/api/vi/user")
    public @ResponseBody String user(){
        return "<h1>user</h1>";
    }

    @GetMapping("/api/vi/manager")
    public @ResponseBody String manager(){
        return "manager";
    }
    @GetMapping("/api/vi/admin")
    public @ResponseBody String admin(){
        return "admin";
    }

}
