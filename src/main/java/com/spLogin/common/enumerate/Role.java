package com.spLogin.common.enumerate;

import java.util.List;

public enum Role {
  USER, ADMIN;

  public static String[] toStringArray(List<Role> roles) {
    return roles.stream()
        .map(Role::name)
        .toArray(String[]::new);
  }
}
