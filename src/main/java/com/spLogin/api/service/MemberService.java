package com.spLogin.api.service;

import com.spLogin.common.exception.CustomException;
import com.spLogin.common.exception.ErrorCode;
import com.spLogin.api.repository.MemberRepository;
import com.spLogin.api.domain.request.LoginRequest;
import com.spLogin.api.domain.request.RegisterRequest;
import com.spLogin.common.dto.TokenDTO;
import com.spLogin.common.dto.TokenRequestDTO;
import com.spLogin.api.domain.response.UpdatePasswordDTO;
import com.spLogin.api.domain.response.UserResponse;
import com.spLogin.api.domain.entity.Member;
import com.spLogin.common.provider.JwtTokenProvider;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class MemberService {

  private final MemberRepository userRepository;
  private final JwtTokenProvider jwtTokenProvider;
  private final StringRedisTemplate redisTemplate;
  private final AuthenticationManagerBuilder authenticationManagerBuilder;
  @Autowired
  PasswordEncoder passwordEncoder;

  private static final String EMAIL_REGEX =
      "^[a-zA-Z0-9_+&*-]+(?:\\." +
          "[a-zA-Z0-9_+&*-]+)*@" +
          "(?:[a-zA-Z0-9-]+\\.)+[a-z" +
          "A-Z]{2,7}$";

  public UserResponse register(RegisterRequest registerRequest) {
    userRepository.findUserByEmail(registerRequest.getEmail())
        .ifPresent(user -> {
          throw new CustomException(ErrorCode.ALREADY_USER, ErrorCode.ALREADY_USER.getMessage());
        });
    Pattern pattern = Pattern.compile(EMAIL_REGEX);
    if (!pattern.matcher(registerRequest.getEmail()).matches()) {
      throw new CustomException(ErrorCode.INVALID_EMAIL_FORM, ErrorCode.INVALID_EMAIL_FORM.getMessage());
    }

    if (!verifyPassword(registerRequest.getPassword())) {
      throw new CustomException(ErrorCode.INVALID_PASSWORD_FORM, ErrorCode.INVALID_PASSWORD_FORM.getMessage());
    }

    if (userRepository.findUserByNickname(registerRequest.getNickname()).isPresent()) {
      throw new CustomException(ErrorCode.ALREADY_NICKNAME, ErrorCode.ALREADY_NICKNAME.getMessage());
    }

    Member newUser = Member.createNewUser(passwordEncoder, registerRequest);
    userRepository.save(newUser);

    return userToUserResponse(newUser);
  }

  @Transactional(readOnly = true)
  public TokenDTO login(LoginRequest loginRequest) {

    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
        loginRequest.getEmail(), loginRequest.getPassword());
    Authentication authentication = authenticationManagerBuilder.getObject().authenticate(token);

    return getTokenDTO(authentication);
  }

  public TokenDTO reissue(TokenRequestDTO tokenRequestDTO) {
    if (!jwtTokenProvider.validateToken(tokenRequestDTO.getAccessToken())) {
      throw new CustomException(ErrorCode.INVALID_TOKEN, ErrorCode.INVALID_TOKEN.getMessage());
    }

    Authentication authentication = jwtTokenProvider.getAuthentication(tokenRequestDTO.getAccessToken());
    String refreshToken = redisTemplate.opsForValue().get("RT:" + tokenRequestDTO.getAccessToken());
    if (refreshToken == null || !refreshToken.equals(tokenRequestDTO.getRefreshToken())) {
      throw new CustomException(ErrorCode.NOT_MATCH_TOKEN_INFO, ErrorCode.NOT_MATCH_TOKEN_INFO.getMessage());
    }

    return getTokenDTO(authentication);
  }

  public void logout(TokenRequestDTO tokenRequestDTO) {
    if (!jwtTokenProvider.validateToken(tokenRequestDTO.getAccessToken())) {
      throw new CustomException(ErrorCode.INVALID_TOKEN, ErrorCode.INVALID_TOKEN.getMessage());
    }

    if (redisTemplate.opsForValue().get("RT:" + tokenRequestDTO.getAccessToken()) != null) {
      redisTemplate.delete("RT:" + tokenRequestDTO.getAccessToken());
    }
  }

  public void updatePassword(UpdatePasswordDTO updatePasswordDTO) {
    Member user = userRepository.findUserByEmail(updatePasswordDTO.getEmail())
        .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND, ErrorCode.USER_NOT_FOUND.getMessage()));

    if (!verifyPassword(updatePasswordDTO.getPassword())) {
      throw new CustomException(ErrorCode.INVALID_PASSWORD_FORM, ErrorCode.INVALID_PASSWORD_FORM.getMessage());
    }
    user.changePassword(passwordEncoder.encode(updatePasswordDTO.getPassword()));
  }

  private TokenDTO getTokenDTO(Authentication authentication) {
    TokenDTO tokenDTO = jwtTokenProvider.generateTokenDTO(authentication);

    redisTemplate.opsForValue()
        .set("RT:" + tokenDTO.getAccessToken(),
            tokenDTO.getRefreshToken(),
            tokenDTO.getRefreshTokenExpiresIn(),
            TimeUnit.MILLISECONDS);

    return tokenDTO;
  }

  private UserResponse userToUserResponse(Member user) {
    return new UserResponse(
        user.getNickname(),
        user.getEmail()
    );
  }

  public static boolean verifyPassword(String userPassword) {
    String passwordPolicy = "((?=.*[a-z])(?=.*[0-9])(?=.*[^a-zA-Z0-9]).{8,})";
    Pattern pattern = Pattern.compile(passwordPolicy);
    Matcher matcher= pattern.matcher(userPassword);

    return matcher.matches();
  }

}
