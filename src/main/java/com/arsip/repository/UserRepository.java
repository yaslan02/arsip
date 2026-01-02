package com.arsip.repository;


import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.arsip.entity.MstUser;

@Repository
public interface UserRepository extends JpaRepository<MstUser, Long>, JpaSpecificationExecutor<MstUser>{
	@Query(value = "select * from mst_user where lower(username) = lower(:username)", nativeQuery = true)
	List<MstUser> findByUsername(@Param("username") String username);
	@Query(value = "select * from mst_user where role= 'Karyawan'", nativeQuery = true)
	List<MstUser> findAllKaryawan();
}
