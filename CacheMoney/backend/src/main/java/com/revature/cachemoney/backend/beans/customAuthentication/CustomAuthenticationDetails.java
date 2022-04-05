package com.revature.cachemoney.backend.beans.customAuthentication;

import org.springframework.security.web.authentication.WebAuthenticationDetails;
import javax.servlet.http.HttpServletRequest;

public class CustomAuthenticationDetails extends WebAuthenticationDetails{

    private String user2FaCode;

    public CustomAuthenticationDetails(HttpServletRequest request)
    {
        super(request);
        System.out.println(request.getRequestURI() + " :: " + request.getParameter("2facode"));
        this.user2FaCode = request.getParameter("2facode");
    }

    public String getUser2FaCode(){return user2FaCode;}
}
