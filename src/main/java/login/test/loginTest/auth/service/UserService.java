package login.test.loginTest.auth.service;


import login.test.loginTest.auth.configure.auth.TokenProvider;
import login.test.loginTest.auth.entity.Role;
import login.test.loginTest.auth.entity.UserEntity;
import login.test.loginTest.auth.model.Token;
import login.test.loginTest.auth.model.request.JoinRequest;
import login.test.loginTest.auth.model.request.LoginRequest;
import login.test.loginTest.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@RequiredArgsConstructor
@Service
public class UserService {

    private final RedisTemplate<String, String> redisTemplate;
    private final UserRepository userRepository;
    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final PasswordEncoder passwordEncoder;

    @Value("${spring.auth.jwt.refresh_time}")
    private Long REFRESH_TOKEN_EXPIRE_TIME;

    public void join(JoinRequest request) throws Exception {


        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new Exception("이미 존재하는 이메일입니다.");
        }

        if (userRepository.findByNickname(request.getNickname()).isPresent()) {
            throw new Exception("이미 존재하는 닉네임입니다.");
        }

        UserEntity user = UserEntity.builder()
                .email(request.getEmail())
                .password(request.getPassword())
                .nickname(request.getNickname())
                .age(request.getAge())
                .city(request.getCity())
                .role(Role.USER)
                .build();

        user.passwordEncode(passwordEncoder);
        userRepository.save(user);
    }
    public Token login(LoginRequest request) {
        UserEntity entity =userRepository.findByEmail(request.getEmail()).orElseThrow(() -> new IllegalArgumentException("가입되지 않은 E-MAIL 입니다."));
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(request.getEmail(),request.getPassword());
        String username = authenticationToken.getName();
        Token token = tokenProvider.generateToken(entity);
        redisTemplate.opsForValue().set(
                username,
                token.getRefreshToken(),
                REFRESH_TOKEN_EXPIRE_TIME,
                TimeUnit.MILLISECONDS
        );

        return token;

    }

    public String reissue(String token){
        Authentication authentication = tokenProvider.getAuthentication(token);
        String refreshToken = (String) redisTemplate.opsForValue().get(authentication.getName());

        return refreshToken;
    }
}


