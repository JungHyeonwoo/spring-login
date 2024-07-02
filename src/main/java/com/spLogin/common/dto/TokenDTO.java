package com.spLogin.common.dto;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class TokenDTO {

  private String grantType;
  private String accessToken;
  private String refreshToken;
  private Long accessTokenExpiresIn;
  private Long refreshTokenExpiresIn;

  @Builder(builderClassName = "of", builderMethodName = "of")
  public TokenDTO(String grantType, String accessToken, String refreshToken, Long accessTokenExpiresIn, Long refreshTokenExpiresIn) {
    this.grantType = grantType;
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.accessTokenExpiresIn = accessTokenExpiresIn;
    this.refreshTokenExpiresIn = refreshTokenExpiresIn;
  }

}
