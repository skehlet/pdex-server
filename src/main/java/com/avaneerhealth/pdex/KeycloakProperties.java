package com.avaneerhealth.pdex;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Getter;
import lombok.Setter;

@Configuration
@ConfigurationProperties(prefix = "keycloak")
public class KeycloakProperties {
  @Getter @Setter
	Boolean enableAuth;
  @Getter @Setter
  String jwksUrl;
  @Getter @Setter
  String issuer;
}
