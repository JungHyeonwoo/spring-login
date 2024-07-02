package com.spLogin.common.exception;

import lombok.Getter;

@Getter
public enum AuthErrorCode {
  INVALID_TOKEN("INVALID_TOKEN", "유효하지 않은 토큰입니다."),
  NOT_MATCH_TOKEN_INFO("NOT_MATCH_TOKEN_INFO", "토큰 정보가 일치하지 않습니다."),
  ENTERED_ID_AND_PASSWORD("ENTERED_ID_AND_PASSWORD", "아이디와 비밀번호를 입력해주세요."),
  ALREADY_JOIN_USER("ALREADY_JOIN_USER", "이미 존재하는 아이디입니다."),
  PASSWORD_NOT_ENOUGH_CONDITION("PASSWORD_NOT_ENOUGH_CONDITION","패스워드 조건을 만족하지 못했습니다."),
  ACCESS_DENIED("ACCESS_DENIED", "접근 거부되었습니다."),
  NOT_MATCH_PASSWORD("NOT_MATCH_PASSWORD", "패스워드가 일치하지 않습니다."),
  UNKNOWN_ERROR("UNKNOWN_ERROR", "알 수 없는 에러 발생"),
  WRONG_TOKEN("WRONG_TOKEN", "잘못된 토큰입니다."),
  UNSUPPORTED_TOKEN("UNSUPPORTED_TOKEN", "지원하지 않는 방식의 토큰입니다."),
  EXPIRED_TOKEN("EXPIRED_TOKEN", "기간이 만료된 토큰입니다."),
  WRONG_TYPE_TOKEN("WRONG_TYPE_TOKEN", "잘못된 타입의 토큰입니다."),
  LOG_OUT_USER("LOG_OUT_USER", "로그아웃한 유저입니다."),
  NOT_AUTH_TOKEN("NOT_AUTH_TOKEN", "권한 정보가 없는 토큰입니다.");
  private final String code;
  private final String message;

  AuthErrorCode(String code, String message) {
    this.code = code;
    this.message = message;
  }
}