package login.test.loginTest.auth.repository;



import login.test.loginTest.auth.entity.SocialType;
import login.test.loginTest.auth.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.*;


public interface UserRepository extends JpaRepository<UserEntity,Long> {

    Optional<UserEntity> findByEmail(String Email);

    Optional<UserEntity> findByNickname(String nickname);

    Optional<UserEntity> findByRefreshToken(String refreshToken);

    Optional<UserEntity> findBySocialTypeAndSocialId(SocialType socialType, String socialId);

}
