package com.spLogin.common.config;

import com.spLogin.common.handler.JwtAccessDeniedHandler;
import com.spLogin.common.handler.JwtAuthenticationEntryPoint;
import com.spLogin.common.provider.JwtTokenProvider;
import javax.servlet.DispatcherType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  private final JwtTokenProvider jwtTokenProvider;
  private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
  private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
  private final StringRedisTemplate stringRedisTemplate;


  @Override
  protected void configure(final HttpSecurity http) throws Exception {
    http
        .csrf().disable()
        .httpBasic().disable()
        .exceptionHandling()
        .authenticationEntryPoint(jwtAuthenticationEntryPoint)
        .accessDeniedHandler(jwtAccessDeniedHandler)
        .and()
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .authorizeRequests()
        .antMatchers("/v1/user/**"
            , "/api/application/latest"
            , "/swagger-resources/**"
            , "/swagger-ui/**"
            , "/deviceconn/renewAdb"
            , "/api/mobiles/checkDevice"
            , "/api/mobiles/sync"
            , "/api/mobiles/connect/**"
            , "/api/mobiles/update-connection"
            , "/devices/renewAdb"
            , "/api/server/**"
            , "/api/certifications/**"
            , "/api/alarms/**"
            , "/v3/api-docs").permitAll()
        .antMatchers(HttpMethod.GET, "/api/products").permitAll()
        .anyRequest().authenticated()
        .and()
        .apply(new JwtSecurityConfig(jwtTokenProvider,stringRedisTemplate));
  }

  @Bean
  public BCryptPasswordEncoder passwordEncoder(){
    return new BCryptPasswordEncoder();
  }

  @Override
  public void configure(WebSecurity web) throws Exception {
    web.ignoring()
        .antMatchers("/h2-console/**", "favicon.ico");
  }
}