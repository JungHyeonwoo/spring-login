package com.spLogin.common.config;


import com.spLogin.common.provider.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

  private final JwtTokenProvider jwtTokenProvider;

  private final StringRedisTemplate redisTemplate;

  @Override
  public void configure(HttpSecurity http) throws Exception {
    UserAuthenticationFilter customFilter = new UserAuthenticationFilter(jwtTokenProvider,redisTemplate);
    http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
  }
}