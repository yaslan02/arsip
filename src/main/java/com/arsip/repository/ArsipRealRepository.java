package com.arsip.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import com.arsip.entity.MstArsip;
import com.arsip.entity.MstArsipReal;

public interface ArsipRealRepository extends JpaRepository<MstArsipReal, Long>, JpaSpecificationExecutor<MstArsipReal>{

}
