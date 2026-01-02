package com.arsip.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.arsip.entity.MstJabatan;
import com.arsip.entity.MstRiwayat;
import com.arsip.entity.MstUser;
import com.arsip.repository.JabatanRepository;
import com.arsip.repository.RiwayatRepository;
import com.arsip.repository.UserRepository;
import com.arsip.service.UserService;

@Service
public class UserServiceImpl implements UserService{
	
	@Autowired
	private UserRepository repo;
	
	@Autowired
	private JabatanRepository repoJabatan;
	
	@Autowired
	private RiwayatRepository repoRiwayat;

	@Override
	public String saveUser(MstUser user) {
		String result = "";
		try {
			repo.save(user);
			result = "200";
		} catch (Exception e) {
			e.printStackTrace();
			result = "500";
		}
		
		return result;
	}

	@Override
	public String saveJabatan(MstJabatan jabatan) {
		String result = "";
		try {
			repoJabatan.save(jabatan);
			result = "200";
		} catch (Exception e) {
			e.printStackTrace();
			result = "500";
		}
		
		return result;
	}

	@Override
	public String saveRiwayat(MstRiwayat riwayat) {
		String result = "";
		try {
			repoRiwayat.save(riwayat);
			result = "200";
		} catch (Exception e) {
			e.printStackTrace();
			result = "500";
		}
		
		return result;
	}

}
