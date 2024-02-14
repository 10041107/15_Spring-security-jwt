package com.ohgiraffers.security.auth.model;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

public class DetailsUser implements UserDetails {

    private User user;


    public DetailsUser() {
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        Collection<GrantedAuthority> authorities = new ArrayList<>();
        user.getRoleList().forEach(role -> authorities.add(() -> role));
        return authorities;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return null;
    }
    //** 잠겨있는 계정을 확인하는 메소드
    @Override
    public boolean isAccountNonExpired() {
        return false;
    }


    //계정 만료 여부를 표현하는 메소드
    @Override
    public boolean isAccountNonLocked() {
        return false;
    }
    //탈퇴 계정 여부를 표현하는 메소드
    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    //계정 비활성화 여부로 사용자가 사용할 수 없는 상태
    @Override
    public boolean isEnabled() {
        return false;
    }

    public User getUser() {
    }
}
