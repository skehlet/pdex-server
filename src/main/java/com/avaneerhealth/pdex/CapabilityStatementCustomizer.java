package com.avaneerhealth.pdex;

import java.util.ArrayList;

import org.hl7.fhir.instance.model.api.IBaseConformance;
import org.hl7.fhir.r4.model.CapabilityStatement;
import org.hl7.fhir.r4.model.CodeableConcept;
import org.hl7.fhir.r4.model.Extension;
import org.hl7.fhir.r4.model.UriType;
import org.hl7.fhir.r4.model.CapabilityStatement.CapabilityStatementRestSecurityComponent;

import ca.uhn.fhir.interceptor.api.Hook;
import ca.uhn.fhir.interceptor.api.Interceptor;
import ca.uhn.fhir.interceptor.api.Pointcut;
import ca.uhn.fhir.rest.server.servlet.ServletRequestDetails;

@Interceptor
public class CapabilityStatementCustomizer {

  KeycloakProperties keycloakProperties;

  public CapabilityStatementCustomizer(KeycloakProperties keycloakProperties) {
    this.keycloakProperties = keycloakProperties;
  }
  
  @Hook(Pointcut.SERVER_CAPABILITY_STATEMENT_GENERATED)
  public void customize(IBaseConformance theCapabilityStatement, ServletRequestDetails theRequest) {

    CapabilityStatement cs = (CapabilityStatement) theCapabilityStatement;

    cs.getSoftware().setName("PDex Server (Avaneer Health)");

    // add support for older clients expecting security properties from STU1
    CodeableConcept service = new CodeableConcept();
    service.addCoding().setSystem("http://hl7.org/fhir/restful-security-service").setCode("OAuth");
    service.setText("OAuth2 using Client Credentials");
    Extension oauthExtension = new Extension();
    ArrayList<Extension> uris = new ArrayList<Extension>();
    uris.add(new Extension("authorize", new UriType(keycloakProperties.getAuthorizationUrl())));
    uris.add(new Extension("introspect", new UriType(keycloakProperties.getIntrospectionUrl())));
    uris.add(new Extension("token", new UriType(keycloakProperties.getTokenUrl())));
    oauthExtension.setUrl("http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris");
    oauthExtension.setExtension(uris);

    CapabilityStatementRestSecurityComponent security = new CapabilityStatementRestSecurityComponent();
    security.addService(service);
    security.addExtension(oauthExtension);
    cs.getRest().get(0).setSecurity(security);

  }

}
