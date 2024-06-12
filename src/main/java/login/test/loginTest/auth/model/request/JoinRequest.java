package login.test.loginTest.auth.model.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class JoinRequest {
    private String email;
    private String password;
    private String nickname;
    private int age;
    private String city;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
