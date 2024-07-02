package com.spLogin.api.repository;

import com.spLogin.api.domain.entity.Member;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, Long> {

  Optional<Member> findUserByEmail(String email);

  Optional<Member> findUserByNickname(String nickname);

  Optional<Member> findByEmailAndIsDeletedFalse(String email);

}
