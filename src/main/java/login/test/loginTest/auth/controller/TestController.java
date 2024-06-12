package login.test.loginTest.auth.controller;


import jakarta.servlet.http.HttpServletRequest;
import login.test.loginTest.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@RequiredArgsConstructor // final이 붙거나 @NotNull 이 붙은 필드의 생성자를 자동 생성해주는 롬복 어노테이션
@RequestMapping("/api/v1")
public class TestController {

    private final UserService testController;
    public static final String AUTHORIZATION_HEADER = "Authorization";

    @PostMapping("/test")
    public String test(){
        System.out.println("test");
        return "테스트 통과";
    }

    @GetMapping("/username")
    @ResponseBody
    public String currentUserName(Principal principal) {
        System.out.println(principal.toString());
        return principal.getName();
    }

    @GetMapping("/reissue")
    public String reissue(HttpServletRequest request){
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        String tt = testController.reissue(bearerToken.substring(7));
        System.out.println(tt);
        return tt;
    }
}
