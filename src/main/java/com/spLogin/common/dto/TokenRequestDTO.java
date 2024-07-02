package com.spLogin.common.dto;

import javax.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
@Data
@AllArgsConstructor
public class TokenRequestDTO {
  @NotBlank(message = "잘못된 요청입니다.")
  String accessToken;
  @NotBlank(message = "잘못된 요청입니다.")
  String refreshToken;
}
