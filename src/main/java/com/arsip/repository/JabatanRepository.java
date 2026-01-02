package com.arsip.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.arsip.entity.MstJabatan;

@Repository
public interface JabatanRepository extends JpaRepository<MstJabatan, Long>, JpaSpecificationExecutor<MstJabatan>{
	@Query(value = "select * from mst_jabatan where lower(name) = lower(:name)", nativeQuery = true)
	List<MstJabatan> findByName(@Param("name") String name);
}
