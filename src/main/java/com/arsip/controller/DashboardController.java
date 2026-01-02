package com.arsip.controller;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import com.fasterxml.jackson.databind.ObjectMapper;



@Controller
public class DashboardController extends AppController{
	
	
	@GetMapping("/dashboard")
	public ModelAndView list(ModelAndView mav, Authentication authentication, HttpServletRequest request) {
		mav.addObject("username", authentication.getName());
		return renderPage("dashboard", mav, authentication, request);
	}
	
}
