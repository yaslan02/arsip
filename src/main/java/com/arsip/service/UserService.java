package com.arsip.service;

import com.arsip.entity.MstJabatan;
import com.arsip.entity.MstRiwayat;
import com.arsip.entity.MstUser;

public interface UserService {
	String saveUser (MstUser user);
	String saveJabatan (MstJabatan jabatan);
	String saveRiwayat (MstRiwayat riwayat);
}
