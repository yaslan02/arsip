package com.arsip.controller;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.arsip.entity.MstArsip;
import com.arsip.entity.MstArsipReal;
import com.arsip.entity.MstRiwayat;
import com.arsip.repository.ArsipRealRepository;
import com.arsip.repository.ArsipRepository;
import com.arsip.repository.UserRepository;
import com.arsip.service.ArsipService;
import com.arsip.service.impl.UserServiceImpl;

@Controller
public class ArsipController extends AppController{
	
	private final String FOLDER_NAME_ARSIP = "arsip";
	
	@Autowired
	private ArsipRepository repo;
	
	@Autowired
	private ArsipRealRepository repoReal;

	@Autowired
	private UserRepository repoUser;
	
	@Autowired
	private ArsipService service;
	
	@Autowired
	private UserServiceImpl userService;
	
	@GetMapping(value = "/arsip")
	public ModelAndView indexArsip(ModelAndView mav, Authentication authentication, HttpServletRequest request) {
		Object principal = authentication.getPrincipal();
		String username;
		if (principal instanceof UserDetails) {
		    username = ((UserDetails) principal).getUsername();
		} else {
		    username = principal.toString();
		}
		
		if(username.equals("superadmin")) {
			mav.addObject("user", "Admin");
		}else {
			mav.addObject("user", repoUser.findByUsername(username).get(0).getRole());
		}
		
		mav.addObject("listArsip", repoReal.findAll());
		
		return renderPage(FOLDER_NAME_ARSIP + "/index", mav, authentication, request);
	}
	
	@GetMapping(value = "/arsip/new")
	public ModelAndView createArsip(ModelAndView mav, Authentication authentication, HttpServletRequest request) {
		mav.addObject("arsip", new MstArsip());
		
		return renderPage(FOLDER_NAME_ARSIP + "/create", mav, authentication, request);
	}
	
	@PostMapping("/arsip/save")
	public String saveArsip(@RequestParam("files") MultipartFile[] files, @RequestParam("docName") String docName, Authentication authentication, RedirectAttributes attributes, HttpServletRequest request) throws IOException {

		List<MstArsip> count = repo.findAll();
		List<MstArsip> arsips = new ArrayList<MstArsip>();
		String filenames = "";
		for (MultipartFile file : files) {
			MstArsip arsip = new MstArsip();
            String fileContentType = file.getContentType();
            byte[] fileBytes = file.getBytes();
            String fileName = file.getOriginalFilename();
            arsip.setContent(Base64.getEncoder().encodeToString(fileBytes));
            arsip.setDocCode("DC-"+LocalDate.now().format(DateTimeFormatter.ofPattern("ddMMyyyy"))+"-"+(count.size()+1));
            arsip.setDocName(docName);
            arsip.setFileName(fileName);
            arsip.setFileType(fileContentType);
            arsip.setUploadDate(new Date());
            arsip.setDecision("waiting");
            
            arsips.add(arsip);
            
            filenames = filenames.concat(fileName).concat(" ");
        }
      
		String result = service.saveArsip(arsips);
		
		Object principal = authentication.getPrincipal();
		String username;
		String jabatan = "";
		if (principal instanceof UserDetails) {
		    username = ((UserDetails) principal).getUsername();
		} else {
		    username = principal.toString();
		}
		
		if(username.equals("superadmin")) {
			jabatan = "Admin";
		}else {
			jabatan = repoUser.findByUsername(username).get(0).getRole();
		}
		
		MstRiwayat riwayat = new MstRiwayat();
		riwayat.setCreatedAt(new Date());
	    riwayat.setNameUser(authentication.getName());
	    riwayat.setAction("arsip");
	    riwayat.setJabatan(jabatan);
	    riwayat.setDesription("Uploaded File "+filenames);
	    userService.saveRiwayat(riwayat);
	    
	    if (result.equals("200")) {
			attributes.addFlashAttribute("status", "success");
			attributes.addFlashAttribute("message", "Success! Data has been successfully inserted.");	    	
	    } else {
			attributes.addFlashAttribute("status", "failed");
			attributes.addFlashAttribute("message", "Failed! Data failed to inserted.");	    	
	    }
		
		return "redirect:/arsip/new";
	}
	
	@GetMapping(value = "/arsip/{id}")
	public String delete(ModelAndView mav, @PathVariable("id") Long id, Authentication authentication, HttpServletRequest request) {
		repo.deleteById(id);
		
		return "redirect:/arsip";
	}
	
	@GetMapping(value = "/arsip/temp")
	public ModelAndView indexArsipTemp(ModelAndView mav, Authentication authentication, HttpServletRequest request) {
		Object principal = authentication.getPrincipal();
		String username;
		if (principal instanceof UserDetails) {
		    username = ((UserDetails) principal).getUsername();
		} else {
		    username = principal.toString();
		}
		
		if(username.equals("superadmin")) {
			mav.addObject("user", "Admin");
		}else {
			mav.addObject("user", repoUser.findByUsername(username).get(0).getRole());
		}
		
		mav.addObject("listArsip", repo.findAll());
		
		return renderPage(FOLDER_NAME_ARSIP + "/reviewIndex", mav, authentication, request);
	}
	
	@GetMapping(value = "/arsip/{id}/{decision}")
	public String editArsip(ModelAndView mav, @PathVariable("id") Long id, @PathVariable("decision") String decision, 
			@RequestParam("comment") String comment, Authentication authentication, HttpServletRequest request, RedirectAttributes attributes) {
		MstArsip arsip = repo.findById(id).get();
		if("approve".equals(decision)) {
			MstArsipReal arsipReal = new MstArsipReal();
			arsipReal.setContent(arsip.getContent());
			arsipReal.setDocCode(arsip.getDocCode());
			arsipReal.setDocName(arsip.getDocName());
			arsipReal.setFileName(arsip.getFileName());
			arsipReal.setFileType(arsip.getFileType());
			arsipReal.setUploadDate(new Date());
			arsipReal.setComment(comment);
			repoReal.save(arsipReal);
			repo.deleteById(id);
		}else {
			arsip.setDecision("rejected");
			arsip.setComment(comment);
		}
		
		Object principal = authentication.getPrincipal();
		String username;
		String jabatan = "";
		if (principal instanceof UserDetails) {
		    username = ((UserDetails) principal).getUsername();
		} else {
		    username = principal.toString();
		}
		
		if(username.equals("superadmin")) {
			jabatan = "Admin";
		}else {
			jabatan = repoUser.findByUsername(username).get(0).getRole();
		}
		
		MstRiwayat riwayat = new MstRiwayat();
		riwayat.setCreatedAt(new Date());
	    riwayat.setNameUser(authentication.getName());
	    riwayat.setAction("arsip");
	    riwayat.setJabatan(jabatan);
	    riwayat.setDesription(decision.toUpperCase() +" File "+arsip.getFileName());
	    userService.saveRiwayat(riwayat);
	  
		attributes.addFlashAttribute("status", "success");
		attributes.addFlashAttribute("message", "Success! Data has been successfully "+decision);
		
		return "redirect:/arsip/temp";
	}

}
