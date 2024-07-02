package com.spLogin.api.domain.entity;

import static com.spLogin.common.enumerate.Role.USER;

import com.spLogin.api.domain.request.RegisterRequest;
import com.spLogin.common.entity.BaseEntity;
import com.spLogin.common.enumerate.Role;
import java.io.Serializable;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;

@Entity
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Member extends BaseEntity implements Serializable {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;
  @Column(nullable = false, unique = true)
  private String email;
  @Column(nullable = false)
  private String password;
  @Column(nullable = false, unique = true)
  private String nickname;
  @Enumerated(EnumType.STRING)
  private Role role;
  @Column(name = "is_deleted")
  private boolean isDeleted;


  public boolean isPasswordMatch(PasswordEncoder passwordEncoder, String password) {
    return passwordEncoder.matches(password, this.password);
  }

  public void changePassword(String password) {
    this.password = password;
  }

  public static Member createNewUser(PasswordEncoder passwordEncoder, RegisterRequest registerRequest) {
    String encryptedPassword = passwordEncoder.encode(registerRequest.getPassword());

    return Member.builder()
        .email(registerRequest.getEmail())
        .password(encryptedPassword)
        .nickname(registerRequest.getNickname())
        .role(USER)
        .isDeleted(false)
        .build();
  }
}
