package com.mcx.clientApp;

import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

public class ExternalSignatureService {
	Logger logger = LoggerFactory.getLogger(ExternalSignatureService.class);
	@Autowired
	private RestTemplate restTemplate;

	public byte[] signedHash(byte[] hash) {
		logger.info("Hash value sent by client application is :: {}", Arrays.toString(hash));
		HttpEntity<byte[]> entity = new HttpEntity<>(hash);
		
		long startTime= System.currentTimeMillis();
		ResponseEntity<HSResult> responseEntity = restTemplate.postForEntity("http://localhost:8082/sign", entity,
				HSResult.class);
		long endTime= System.currentTimeMillis();
		
		logger.info("Time taken by back-end service in signing hash which includes network time and processing time at backend service:: {}", (endTime-startTime));
		
		HSResult apiResult = responseEntity.getBody();
		byte[] signedHash = (byte[]) apiResult.getData();
		logger.info("Signed Hash value retrieved by client application is :: {}", Arrays.toString(signedHash));
		return signedHash;

	}
}
