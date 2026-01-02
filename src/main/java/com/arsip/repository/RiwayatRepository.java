package com.arsip.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import com.arsip.entity.MstRiwayat;

@Repository
public interface RiwayatRepository extends JpaRepository<MstRiwayat, Long>, JpaSpecificationExecutor<MstRiwayat>{

}
