package com.arsip.service;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface ExportService {
	
	void exportExcel(HttpServletResponse response, HttpServletRequest request) throws InterruptedException, IOException;
}
