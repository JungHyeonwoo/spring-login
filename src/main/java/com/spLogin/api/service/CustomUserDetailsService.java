package com.spLogin.api.service;

import com.spLogin.api.domain.entity.Member;
import com.spLogin.api.repository.MemberRepository;
import java.util.Collections;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

  private final MemberRepository memberRepository;
  @Override
  public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
    Member member = memberRepository.findByEmailAndIsDeletedFalse(email)
        .orElseThrow(() -> new UsernameNotFoundException(email + "아이디 또는 비밀번호를 확인해주세요."));
    return createUserDetails(member);
  }

  private UserDetails createUserDetails(Member user) {
    SimpleGrantedAuthority authority = new SimpleGrantedAuthority(user.getRole().toString());
    return new org.springframework.security.core.userdetails.User(
        user.getEmail(),
        user.getPassword(),
        Collections.singleton(authority)
    );
  }
}
