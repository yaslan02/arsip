package com.arsip.config;

import java.util.HashMap;
import java.util.Map;

import javax.persistence.EntityManagerFactory;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.boot.orm.jpa.EntityManagerFactoryBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import com.zaxxer.hikari.HikariDataSource;

@Configuration
@EnableTransactionManagement
@EnableJpaRepositories(entityManagerFactoryRef = "entityManagerFactory", basePackages = { "com.arsip.repository" })
public class ExportDBConfig {
	
//	@Primary
//	@Bean(name = "dataSource")
//	@ConfigurationProperties(prefix = "spring.datasource")
//	public DataSource dataSource() {
//		return DataSourceBuilder.create().build();
//	}
	
	@Primary
	@Bean(name = "dataSource")
	public DataSource dataSource() {
	    HikariDataSource ds = new HikariDataSource();
	    ds.setDriverClassName("org.h2.Driver");
	    ds.setJdbcUrl("jdbc:h2:mem:penjualan;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE");
	    ds.setUsername("sa");
	    ds.setPassword("");
	    return ds;
	}

	@Primary
	@Bean(name = "entityManagerFactory")
	public LocalContainerEntityManagerFactoryBean entityManagerFactory(EntityManagerFactoryBuilder builder,
			@Qualifier("dataSource") DataSource dataSource, Environment env) {
		
		Map<String, Object> properties = new HashMap<>();
		properties.put("hibernate.hbm2ddl.auto", env.getProperty("spring.jpa.hibernate.ddl-auto"));
		properties.put("hibernate.physical_naming_strategy", env.getProperty("hibernate.physical_naming_strategy"));
		return builder.dataSource(dataSource).packages("com.arsip").properties(properties).build();
	}

	@Primary
	@Bean(name = "transactionManager")
	public PlatformTransactionManager transactionManager(
			@Qualifier("entityManagerFactory") EntityManagerFactory entityManagerFactory) {
		return new JpaTransactionManager(entityManagerFactory);
	}

}
