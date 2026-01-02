package com.arsip.controller;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.arsip.entity.MstAbsen;
import com.arsip.entity.MstJabatan;
import com.arsip.entity.MstRiwayat;
import com.arsip.entity.MstUser;
import com.arsip.repository.AbsenRepository;
import com.arsip.repository.JabatanRepository;
import com.arsip.repository.RiwayatRepository;
import com.arsip.repository.UserRepository;
import com.arsip.service.UserService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

@Controller
public class UserController extends AppController{
	
	private final String FOLDER_NAME_USER = "user";
	
	@Autowired
	private UserService service;
	
	@Autowired
	private UserRepository repo;
	
	@Autowired
	private AbsenRepository repoAbsen;
	
	@Autowired
	private JabatanRepository repoJabatan;
	
	@Autowired
	private RiwayatRepository repoRiwayat;
	
	@GetMapping(value = "/user")
	public ModelAndView indexUser(ModelAndView mav, Authentication authentication, HttpServletRequest request) {
		mav.addObject("listUser", repo.findAll());
		
		return renderPage(FOLDER_NAME_USER + "/index", mav, authentication, request);
	}
	
	@GetMapping(value = "/absensi")
	public ModelAndView indexAbsensi(ModelAndView mav, Authentication authentication, HttpServletRequest request) {
		return renderPage(FOLDER_NAME_USER + "/absen", mav, authentication, request);
	}
	
	@GetMapping(value = "/employee")
	public ModelAndView indexEmployee(ModelAndView mav, Authentication authentication, HttpServletRequest request) {
		return renderPage(FOLDER_NAME_USER + "/absenKaryawan", mav, authentication, request);
	}
	
	@GetMapping(value = "/absensi/list")
	@ResponseBody
	public String listAbsensi(Authentication authentication) throws JsonProcessingException {
		SimpleDateFormat date = new SimpleDateFormat("dd MMM yyyy");
		List<Map<String, Object>> user = new ObjectMapper().convertValue(repo.findByUsername(authentication.getName()), new TypeReference<List<Map<String,Object>>>() {
		});
		
		Long id = Long.valueOf(user.get(0).get("id").toString());
		MstAbsen absen = repoAbsen.findKaryawan(id);
		
		user.get(0).put("dateAbsen", date.format(new Date()));
		user.get(0).put("status", absen != null ? absen.getStatus() : "");
		user.get(0).put("alasan", absen != null ? absen.getAlasan() : "");
		
		return new ObjectMapper().writeValueAsString(user.get(0));
	}
	
	@GetMapping(value = "/employee/list")
	@ResponseBody
	public String listEmployee(ModelAndView mav, Authentication authentication, HttpServletRequest request, @RequestParam("startdate") String startdate) throws JsonProcessingException, ParseException {
		SimpleDateFormat date = new SimpleDateFormat("dd MMM yyyy");
		SimpleDateFormat date1 = new SimpleDateFormat("dd-MM-yyyy");
		List<Map<String, Object>> empl = new ObjectMapper().convertValue(repo.findAllKaryawan(), new TypeReference<List<Map<String,Object>>>() {});
		List<MstAbsen> absen = repoAbsen.findAbsenNow(startdate);
		System.out.println(date1.parse(startdate));
		for (Map<String, Object> mstUser : empl) {
			mstUser.put("dateAbsen", date.format(date1.parse(startdate)));
			mstUser.put("status", "Tidak Hadir");
			mstUser.put("alasan", "-");
			for (MstAbsen mstAbsen : absen) {
				if(Long.valueOf(mstUser.get("id").toString()).equals(mstAbsen.getIdUser())) {
					mstUser.put("status", mstAbsen.getStatus());
					mstUser.put("alasan", mstAbsen.getAlasan() != null ? mstAbsen.getAlasan() : "-");
				}
			}
		}
		
		return new ObjectMapper().writeValueAsString(empl);
	}
	
	@GetMapping(value = "/user/new")
	public ModelAndView createUser(ModelAndView mav, Authentication authentication, HttpServletRequest request) {
		mav.addObject("user", new MstUser());
		mav.addObject("listJabatan", repoJabatan.findAll());
		
		return renderPage(FOLDER_NAME_USER + "/create", mav, authentication, request);
	}
	
	@GetMapping(value = "/user/{id}")
	public ModelAndView editUser(ModelAndView mav, @PathVariable("id") Long id, Authentication authentication, HttpServletRequest request) {
		mav.addObject("user", repo.findById(id).orElse(null));
		mav.addObject("listJabatan", repoJabatan.findAll());
		
		return renderPage(FOLDER_NAME_USER + "/edit", mav, authentication, request);
	}
	
	@PostMapping("/user/save")
	public String saveUser(Authentication authentication, RedirectAttributes attributes, @ModelAttribute MstUser user, HttpServletRequest request) {
		List<MstUser> list = repo.findByUsername(user.getUsername());
		
		if(list.size() > 0) {
			attributes.addFlashAttribute("status", "failed");
			attributes.addFlashAttribute("message", "Failed! Username already exist.");	
		}else {
			String result = service.saveUser(user);
			
		    if (result.equals("200")) {
				attributes.addFlashAttribute("status", "success");
				attributes.addFlashAttribute("message", "Success! Data has been successfully added.");	    	
		    } else {
				attributes.addFlashAttribute("status", "failed");
				attributes.addFlashAttribute("message", "Failed! Data failed to add.");	    	
		    }
		}
		return "redirect:/user";
	}
	
	@PostMapping("/user/update")
	public String updateUser(Authentication authentication, RedirectAttributes attributes, 
			@ModelAttribute MstUser user, HttpServletRequest request) {
		
		String result = service.saveUser(user);
		
		if (result.equals("200")) {
			attributes.addFlashAttribute("status", "success");
			attributes.addFlashAttribute("message", "Success! Data has been successfully updated.");	    	
	    } else {
			attributes.addFlashAttribute("status", "failed");
			attributes.addFlashAttribute("message", "Failed! Data failed to updated.");	    	
	    }
		
		return "redirect:/user";
	}
	
	@GetMapping("/absen/save")
	@ResponseBody
	public String saveAbsen(@RequestParam("idUser") Long idUser, @RequestParam("status") String status, @RequestParam(required = false) String alasan) {
		MstAbsen absen = new MstAbsen();
		absen.setIdUser(idUser);
		absen.setStatus(status);
		absen.setAlasan(alasan);
		repoAbsen.save(absen);
		return "200";
	}
	
	@GetMapping(value = "/jabatan")
	public ModelAndView indexJabatan(ModelAndView mav, Authentication authentication, HttpServletRequest request) {
		mav.addObject("listJabatan", repoJabatan.findAll());
		
		return renderPage(FOLDER_NAME_USER + "/jabatanIndex", mav, authentication, request);
	}
	
	@GetMapping(value = "/jabatan/new")
	public ModelAndView createJabatan(ModelAndView mav, Authentication authentication, HttpServletRequest request) {
		mav.addObject("jabatan", new MstJabatan());
		
		return renderPage(FOLDER_NAME_USER + "/jabatanCreate", mav, authentication, request);
	}
	
	@GetMapping(value = "/jabatan/{id}")
	public ModelAndView editJabatan(ModelAndView mav, @PathVariable("id") Long id, Authentication authentication, HttpServletRequest request) {
		mav.addObject("jabatan", repoJabatan.findById(id).orElse(null));
		
		return renderPage(FOLDER_NAME_USER + "/jabatanEdit", mav, authentication, request);
	}
	
	@PostMapping("/jabatan/save")
	public String saveJabatan(Authentication authentication, RedirectAttributes attributes, @ModelAttribute MstJabatan jabatan, HttpServletRequest request) {
		List<MstJabatan> list = repoJabatan.findByName(jabatan.getName());
		
		if(list.size() > 0) {
			attributes.addFlashAttribute("status", "failed");
			attributes.addFlashAttribute("message", "Failed! Jabatan already exist.");	
		}else {
			jabatan.setCreatedAt(new Date());
			String result = service.saveJabatan(jabatan);
			
		    if (result.equals("200")) {
				attributes.addFlashAttribute("status", "success");
				attributes.addFlashAttribute("message", "Success! Data has been successfully added.");	    	
		    } else {
				attributes.addFlashAttribute("status", "failed");
				attributes.addFlashAttribute("message", "Failed! Data failed to add.");	    	
		    }
		}
		return "redirect:/jabatan";
	}
	
	@PostMapping("/jabatan/update")
	public String updateJabatan(Authentication authentication, RedirectAttributes attributes, 
			@ModelAttribute MstJabatan jabatan, HttpServletRequest request) {
		
		String result = service.saveJabatan(jabatan);
		
		if (result.equals("200")) {
			attributes.addFlashAttribute("status", "success");
			attributes.addFlashAttribute("message", "Success! Data has been successfully updated.");	    	
	    } else {
			attributes.addFlashAttribute("status", "failed");
			attributes.addFlashAttribute("message", "Failed! Data failed to updated.");	    	
	    }
		
		return "redirect:/jabatan";
	}
	
	@GetMapping(value = "/riwayat")
	public ModelAndView indexRiwayat(ModelAndView mav, Authentication authentication, HttpServletRequest request) {
		mav.addObject("listRiwayat", repoRiwayat.findAll());
		
		return renderPage(FOLDER_NAME_USER + "/riwayatIndex", mav, authentication, request);
	}
	
	@PostMapping("/riwayat/save")
	@ResponseBody
	public ResponseEntity<?> saveRiwayat(Authentication authentication,
	                                     @RequestBody MstRiwayat riwayat) {
		
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
			jabatan = repo.findByUsername(username).get(0).getRole();
		}

	    riwayat.setCreatedAt(new Date());
	    riwayat.setNameUser(authentication.getName());
	    riwayat.setJabatan(jabatan);
	    service.saveRiwayat(riwayat);
	    return ResponseEntity.ok().build();
	}

}
