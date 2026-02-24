package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.Customizer;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.spec.SecretKeySpec;

@Configuration
public class ProjectConfig {
	public ProjectConfig() {}
	
	@Bean
	NimbusJwtDecoder jwtDecoder() {
		// No usar en producción
		String keystr = "token-para-hacer-testing-en-el-backend";
		byte key[] = keystr.getBytes();
		SecretKeySpec secretKey = new SecretKeySpec(key, "HmacSHA256");
		
		return NimbusJwtDecoder.withSecretKey(secretKey).build();
	}
	
	@Bean
	JwtAuthenticationProvider jwtAuthProvider(NimbusJwtDecoder decoder) {
		return new JwtAuthenticationProvider(decoder);
	}
	
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthenticationProvider authProvider) throws Exception {
		http.authenticationProvider(authProvider);
		
		http.authorizeHttpRequests(
			c -> c.requestMatchers("/api/administrador")
			.requestMatchers("/api/apelacion")
			.requestMatchers("/api/beca")
			.requestMatchers("/api/docpostulacion")
			.requestMatchers("/api/documentos")
			.requestMatchers("/api/estudiante")
			.requestMatchers("/api/postulacion")
			.hasAuthority("SCOPE_estudiante").anyRequest().authenticated()
		)
			.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
		
		return http.build();
	}
}