package com.ohgiraffers.security.auth.filter;

import ch.qos.logback.core.pattern.ConverterUtil;
import ch.qos.logback.core.subst.Token;
import com.ohgiraffers.security.auth.model.DetailsUser;
import com.ohgiraffers.security.common.AuthConstants;
import com.ohgiraffers.security.common.utills.ConvertUtil;
import com.ohgiraffers.security.common.utills.TokenUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Objects;

@Configuration
public class CustomAuthSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        User user = ((DetailsUser) authentication.getPrincipal()).getUser();
        JSONObject jsonValue = (JSONObject) ConvertUtil.convertObjectToJsonObject(user);
        HashMap<String, Object> responseMap = new HashMap<>();
        JSONObject jsonObject;

        if(user.getState().equals("N")){
            responseMap.put("userInfo", jsonValue);
            responseMap.put("message", "휴면 상태인 계정입니다.");
        }else {
            String token = TokenUtils.generateJwtToken(user);
            responseMap.put("userInfo", jsonValue);
            responseMap.put("message", "로그인 성공");

            response.addHeader(AuthConstants.AUTH_HEADER, AuthConstants.TOKEN_TYPE + " " + token);
        }

        jsonObject = new JSONObject(responseMap);
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");
        PrintWriter printWriter = response.getWriter();
        printWriter.println(jsonObject);
        printWriter.flush();
        printWriter.close();


    }
}
