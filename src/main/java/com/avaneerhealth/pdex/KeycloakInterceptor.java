/*
Taken from https://groups.google.com/g/hapi-fhir/c/0ewrCc4v_Sk/m/uMSqBJi6AAAJ
*/
package com.avaneerhealth.pdex;

import ca.uhn.fhir.model.primitive.IdDt;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import ca.uhn.fhir.interceptor.api.Interceptor;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;

import org.springframework.beans.factory.annotation.Autowired;

import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;

import org.json.JSONObject;

import java.util.Base64;
import java.util.List;

import static ca.uhn.fhir.rest.api.Constants.URL_TOKEN_METADATA;

/**
 * Created by LarsKristian on 12.09.2016.
 * Updated by Steve Kehlet on 2024-07-09.
 */

@Interceptor
public class KeycloakInterceptor extends AuthorizationInterceptor {

    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KeycloakInterceptor.class);

    KeycloakProperties keycloakProperties;

    public KeycloakInterceptor(KeycloakProperties keycloakProperties) {
        this.keycloakProperties = keycloakProperties;
        logger.info("keycloakProperties.getEnableAuth(): {}", keycloakProperties.getEnableAuth());
        logger.info("keycloakProperties.getJwksUrl(): {}", keycloakProperties.getJwksUrl());
        logger.info("keycloakProperties.getIssuer(): {}", keycloakProperties.getIssuer());
    }

    @Override
    public List<IAuthRule> buildRuleList(RequestDetails theRequestDetails) {

        // No check needed if authentication is disabled
        if (!keycloakProperties.getEnableAuth()) {
            return new RuleBuilder().allowAll().build();
        }

        // Allow access to the metadata endpoint without authentication
        if (isMetadataPath(theRequestDetails)) {
            return new RuleBuilder().allowAll().build();
        }

        // Check if request has authorization header and Bearer token
        if (theRequestDetails.getHeader("Authorization") == null) {
            // Throw an HTTP 401
            throw new AuthenticationException("Missing Authorization header value");
        } else if (!theRequestDetails.getHeader("Authorization").toUpperCase().startsWith("BEARER ")) {
            // logger.error("Bearer not found (do not log in production!) = " + theRequestDetails.getHeader("Authorization"));
            throw new AuthenticationException("Missing Bearer token in Authorization header (must start with 'Bearer')");
        }

        String authHeader = theRequestDetails.getHeader("Authorization");
        String encodedAccessToken = authHeader.split(" ")[1];

        // logger.info("Authorization header (do not log in production!) = " + authHeader);
        // logger.info("encodedAccessToken (do not log in production!) = "+encodedAccessToken);

        JSONObject decodedAccessTokenBody = null;
        boolean isJWTValid = false;
        boolean userIsAdmin = false;
        IdDt userIdPatientId = null;

        try {
            decodedAccessTokenBody = getDecodedJSONObject(encodedAccessToken.split("\\.")[1]);
            isJWTValid = checkNHNAuthorization(encodedAccessToken, decodedAccessTokenBody);
        } catch (Exception e) {
            throw new AuthenticationException("Error parsing Bearer token (is it a valid JWT?)");
        }

        if (isJWTValid) {
            // TODO: Only give access to ONE patient!
            userIsAdmin = true;
            // This user has access only to Patient/1 resources
            //userIdPatientId = new IdDt("Patient", 1L);
        } else {
            // Throw an HTTP 401
            throw new AuthenticationException("Bearer token not accepted");
        }

        // If the user is a specific patient, we create the following rule chain:
        // Allow the user to read anything in their own patient compartment
        // Allow the user to write anything in their own patient compartment
        // If a client request doesn't pass either of the above, deny it
        if (userIdPatientId != null) {
            return new RuleBuilder()
                    .allow().read().allResources().inCompartment("Patient", userIdPatientId).andThen()
                    .allow().write().allResources().inCompartment("Patient", userIdPatientId).andThen()
                    .denyAll()
                    .build();
        }

        // If the user is an admin, allow everything
        if (userIsAdmin) {
            return new RuleBuilder()
                    .allowAll()
                    .build();
        }

        // By default, deny everything. This should never get hit, but it's
        // good to be defensive
        return new RuleBuilder()
                .denyAll()
                .build();
    }

    private boolean checkNHNAuthorization(String encodedAccessToken, JSONObject decodedAccessTokenBody) {
        // Check Access Token
        HttpsJwks httpsJkws = new HttpsJwks(keycloakProperties.getJwksUrl());
        HttpsJwksVerificationKeyResolver httpsJwksKeyResolver = new HttpsJwksVerificationKeyResolver(httpsJkws);
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // the JWT must have an expiration time
                .setAllowedClockSkewInSeconds(180) // allow some leeway in validating time based claims to account for clock skew
                //.setRequireSubject() // the JWT must have a subject claim
                .setExpectedIssuer(keycloakProperties.getIssuer()) // whom the JWT needs to have been issued by
                // .setExpectedAudience("http://apps.ehelselab.com/velferd/api/") // to whom the JWT is intended for
                .setVerificationKeyResolver(httpsJwksKeyResolver)
                .build();
        try
        {
            //  Validate the JWT and process it to the Claims
            JwtClaims jwtClaims = jwtConsumer.processToClaims(encodedAccessToken);
            logger.info("JWT validation succeeded! " + jwtClaims);
            return true;
        }
        catch (InvalidJwtException e)
        {
            logger.info("Invalid JWT! ", e);
            return false;
        }
    }

    private JSONObject getDecodedJSONObject(String encodedString){
        byte[] decoded = Base64.getDecoder().decode(encodedString);
        return new JSONObject(new String(decoded));
    }

	private boolean isMetadataPath(RequestDetails theRequestDetails) {
		return theRequestDetails != null && URL_TOKEN_METADATA.equals(theRequestDetails.getRequestPath());
	}
}
