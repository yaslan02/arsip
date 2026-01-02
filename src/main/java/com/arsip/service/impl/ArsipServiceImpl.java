package com.arsip.service.impl;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.arsip.entity.MstArsip;
import com.arsip.entity.MstArsipReal;
import com.arsip.repository.ArsipRealRepository;
import com.arsip.repository.ArsipRepository;
import com.arsip.service.ArsipService;

@Service
public class ArsipServiceImpl implements ArsipService{
	
	@Autowired
	private ArsipRepository repo;
	
	@Autowired
	private ArsipRealRepository repoReal;

	@Override
	public String saveArsip(List<MstArsip> arsip) {
		String result = "";
		try {
			for(MstArsip ars : arsip) {
				repo.save(ars);
			}
			result = "200";
		} catch (Exception e) {
			e.printStackTrace();
			result = "500";
		}
		return result;
	}

}
