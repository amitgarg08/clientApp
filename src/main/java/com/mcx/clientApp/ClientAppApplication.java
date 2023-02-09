package com.mcx.clientApp;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

@SpringBootApplication
public class ClientAppApplication implements CommandLineRunner {
	public static void main(String[] args) {
		SpringApplication.run(ClientAppApplication.class, args);
	}
	@Bean
	public RestTemplate restTemplate(RestTemplateBuilder builder) {
		return builder
				.build();
	}

	@Bean
	ExternalSignatureService externalService() {
		return new ExternalSignatureService();
	}
	@Override
	public void run(String... args) throws Exception {
		new SignWithPKCS11USB().initSign();		
	}
}
