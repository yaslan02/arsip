package com.arsip.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import com.arsip.entity.MstArsip;

public interface ArsipRepository extends JpaRepository<MstArsip, Long>, JpaSpecificationExecutor<MstArsip>{

}
