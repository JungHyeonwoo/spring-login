package com.spLogin.common.provider;

import com.spLogin.api.service.CustomUserDetailsService;
import com.spLogin.common.exception.AuthErrorCode;
import java.util.Objects;
import javax.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {
  private final PasswordEncoder passwordEncoder;
  private final CustomUserDetailsService customUserDetailsService;

  @Override
  public Authentication authenticate(Authentication authentication) {
    String loginId = authentication.getName();
    String password = authentication.getCredentials().toString();
    UserDetails userDetails = customUserDetailsService.loadUserByUsername(loginId);

    if (isNotMathchers(password, userDetails.getPassword())) {
      HttpServletRequest request = ((ServletRequestAttributes) Objects.requireNonNull(
          RequestContextHolder.getRequestAttributes())).getRequest();
      request.setAttribute("exception", AuthErrorCode.NOT_MATCH_PASSWORD.getCode());

      throw new BadCredentialsException(loginId);
    }
    return new UsernamePasswordAuthenticationToken(userDetails.getUsername(), userDetails.getPassword(), userDetails.getAuthorities());
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return authentication.equals(UsernamePasswordAuthenticationToken.class);
  }

  private boolean isNotMathchers(String password, String userDetailsPassword) {
    return !passwordEncoder.matches(password, userDetailsPassword);
  }
}