package com.arsip.controller;


import javax.servlet.http.HttpServletRequest;

import org.springframework.boot.devtools.restart.Restarter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;


@Controller
public class LoginController {
	
	@GetMapping(value = {"/", "/login"})
	public String login(Model model, String error, RedirectAttributes attributes) {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (!(auth instanceof AnonymousAuthenticationToken)) {
			return "redirect:/dashboard";
		}
		
		if (error != null) {
			attributes.addFlashAttribute("error", "true");
			return "redirect:/login";
		}
		return "login";
	}
	
	@PostMapping(value = "/doLogin")
	public String doLogin(HttpServletRequest request, Model model, String error, @RequestParam("username") String username, @RequestParam("password") String password, RedirectAttributes attributes) {
		attributes.addFlashAttribute("error", "true");
		return "redirect:/login";
	}

	@GetMapping("/logout")
	public String logout(HttpServletRequest request) {
		request.getSession().invalidate();
		return "redirect:/login";
	}

	@GetMapping("/accessDeniedPage")
	public String _403(Authentication auth){
		return "403";
	}
	
	@GetMapping(value = {"/refresh"})
	public ResponseEntity<String> refresh() {
		Runnable run = new Runnable() {
			
			@Override
			public void run() {
				Restarter.getInstance().restart();
			}
		};
		
		Thread tr = new Thread(run);
		tr.start();
		
		return new ResponseEntity<>("Berhasil refresh Apps", HttpStatus.OK);
	}
}
