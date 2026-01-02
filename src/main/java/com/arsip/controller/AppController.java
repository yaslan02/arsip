package com.arsip.controller;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import com.arsip.entity.MstUser;
import com.arsip.repository.UserRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.web.servlet.ModelAndView;

public class AppController {
	
	@Autowired
	private UserRepository repo;
	
    public ModelAndView renderPage(String pageName, ModelAndView mav, Authentication authentication, HttpServletRequest request) {

    	if(authentication.getName().equals("superadmin")) {
    		mav.addObject("access", "Admin");
    	}else {
    		List<MstUser> list = repo.findByUsername(authentication.getName());
    		mav.addObject("access", list.size() > 0 ? list.get(0).getRole() : "");
    	}
		
		mav.addObject("contextPath", request.getContextPath());
		mav.setViewName(pageName);
		
		return mav;
	}
}
