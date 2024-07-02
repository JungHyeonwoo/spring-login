package com.spLogin.common.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@AllArgsConstructor
@Getter
public enum ErrorCode {
  BAD_REQUEST(HttpStatus.BAD_REQUEST, "잘못된 접근입니다."),
  USER_NOT_FOUND(HttpStatus.NOT_FOUND, "사용자를 찾을 수 없습니다."),
  INVALID_TOKEN(HttpStatus.UNAUTHORIZED, "유효하지 않은 토큰입니다."),
  INVALID_EMAIL_FORM(HttpStatus.BAD_REQUEST, "이메일 형식이 올바르지 않습니다."),
  INVALID_PASSWORD_FORM(HttpStatus.BAD_REQUEST, "비밀번호 형식이 올바르지 않습니다."),
  NOT_AUTH_TOKEN(HttpStatus.UNAUTHORIZED, "권한 정보가 없는 토큰입니다."),
  NOT_MATCH_TOKEN_INFO(HttpStatus.UNAUTHORIZED, "토큰 정보가 일치하지 않습니다."),
  ALREADY_USER(HttpStatus.BAD_REQUEST, "이미 가입된 사용자입니다."),
  ALREADY_NICKNAME(HttpStatus.BAD_REQUEST, "이미 사용중인 닉네임입니다.")
  ;

  private final HttpStatus httpStatus;
  private final String message;
}
