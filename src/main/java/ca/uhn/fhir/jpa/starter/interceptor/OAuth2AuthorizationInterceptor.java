package ca.uhn.fhir.jpa.starter.interceptor;

import ca.uhn.fhir.context.FhirVersionEnum;
import ca.uhn.fhir.jpa.starter.AppProperties;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import org.hl7.fhir.instance.model.api.IBaseResource;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import java.util.List;

@Component
public class OAuth2AuthorizationInterceptor extends AuthorizationInterceptor {

	private static final Logger logger = LoggerFactory.getLogger(OAuth2AuthorizationInterceptor.class);
	private final AppProperties appProperties;

	public OAuth2AuthorizationInterceptor(AppProperties appProperties) {
		this.appProperties = appProperties;
	}

	@Override
	public List<IAuthRule> buildRuleList(RequestDetails theRequestDetails) {
		if (!this.appProperties.getOauth2().getEnabled()) {
			return new RuleBuilder().allowAll().build();
		}
		// Get Bearer token
		String authHeader = theRequestDetails.getHeader("Authorization");
		if (authHeader == null) {
			return new RuleBuilder().denyAll().build();
		}
		String[] authHeaders = authHeader.split(" ");
		if (authHeaders.length < 2) {
			return new RuleBuilder().denyAll().build();
		}
		String token = authHeaders[1];
		if (validateToken(token)) {
			List<String> fhirRoles = this.getFHIRRoles(token);
			if (fhirRoles == null) {
				return new RuleBuilder().denyAll().build();
			}
			if (fhirRoles.contains("FHIRAdmin")) {
				return new RuleBuilder().allowAll().build();
			}
			List<IAuthRule> rules = new ArrayList<>();
			if (fhirRoles.contains("FHIRTerminologyAdmin")) {
				rules = this.addFHIRTerminologyAdminRules(rules);
			}
			if (fhirRoles.contains("FHIRCortexReadWrite")) {
				rules = this.addFHIRCortexReadWriteRules(rules);
			}
			return rules;
		}
		return new RuleBuilder().denyAll().build();
	}

	private List<String> getFHIRRoles(String token) {
		DecodedJWT jwt = JWT.decode(token);
		Map<String, Object> resourceAccess = jwt.getClaim("resource_access").asMap();
		if (resourceAccess != null) {
			// Assuming "fhir" is the client ID and you want to access its roles
			Map<String, Object> fhirAccess = (Map<String, Object>) resourceAccess.get("fhir");

			if (fhirAccess != null) {
				// Extract the roles assigned within the "fhir" client
				return (List<String>) fhirAccess.get("roles");
			}
		}
		return null;
	}

	private List<IAuthRule> addFHIRTerminologyAdminRules(List<IAuthRule> rules) {
		List<IAuthRule> newRules = new ArrayList<>(rules);
		FhirVersionEnum fhirVersion = this.appProperties.getFhir_version();
		String fhirVersionName = fhirVersion.name();
		newRules.addAll(new RuleBuilder()
			.allow().write().resourcesOfType("CodeSystem").withAnyId().andThen()
			.allow().read().resourcesOfType("CodeSystem").withAnyId().andThen()
			.allow().delete().resourcesOfType("CodeSystem").withAnyId().andThen().build()
		);
		newRules.addAll(new RuleBuilder()
			.allow().write().resourcesOfType("ValueSet").withAnyId().andThen()
			.allow().read().resourcesOfType("ValueSet").withAnyId().andThen()
			.allow().delete().resourcesOfType("ValueSet").withAnyId().andThen().build()
		);
		newRules.addAll(new RuleBuilder()
			.allow().write().resourcesOfType("ConceptMap").withAnyId().andThen()
			.allow().read().resourcesOfType("ConceptMap").withAnyId().andThen()
			.allow().delete().resourcesOfType("ConceptMap").withAnyId().andThen().build()
		);
		newRules = this.addAllowReadAndAllOperationOfCodeSystem(newRules, fhirVersionName);
		newRules = this.addAllowReadAndAllOperationOfValueSet(newRules, fhirVersionName);
		newRules = this.addAllowReadAndAllOperationOfConceptMap(newRules, fhirVersionName);
		return newRules;
	}

	private List<IAuthRule> addFHIRCortexReadWriteRules(List<IAuthRule> rules) {
		List<IAuthRule> newRules = new ArrayList<>(rules);
		FhirVersionEnum fhirVersion = this.appProperties.getFhir_version();
		String fhirVersionName = fhirVersion.name();

		newRules.addAll(new RuleBuilder()
			.allow().write().resourcesOfType("Patient").withAnyId().andThen()
			.allow().read().resourcesOfType("Patient").withAnyId().andThen()
			.allow().delete().resourcesOfType("Patient").withAnyId().andThen().build()
		);

		newRules = this.addAllowReadAndAllOperationOfCodeSystem(newRules, fhirVersionName);
		newRules = this.addAllowReadAndAllOperationOfValueSet(newRules, fhirVersionName);
		newRules = this.addAllowReadAndAllOperationOfConceptMap(newRules, fhirVersionName);

		return newRules;
	}

	private List<IAuthRule> addAllowReadAndAllOperationOfCodeSystem(List<IAuthRule> rules, String fhirVersionName) {
		List<IAuthRule> newRules = new ArrayList<>(rules);
		Class<? extends IBaseResource> codeSystemClass;
		switch (fhirVersionName) {
			case "R4":
				codeSystemClass = org.hl7.fhir.r4.model.CodeSystem.class;
				break;
			case "R4B":
				codeSystemClass = org.hl7.fhir.r4b.model.CodeSystem.class;
				break;
			case "R5":
				codeSystemClass = org.hl7.fhir.r5.model.CodeSystem.class;
				break;
			default:
				newRules.addAll(new RuleBuilder().denyAll().build());
				return newRules;
		}
		newRules.addAll(new RuleBuilder()
			.allow().read().resourcesOfType("CodeSystem").withAnyId().andThen()
			.allow().operation().withAnyName().onType(codeSystemClass).andAllowAllResponses().andThen()
			.build()
		);
		return newRules;
	}

	private List<IAuthRule> addAllowReadAndAllOperationOfValueSet(List<IAuthRule> rules, String fhirVersionName) {
		List<IAuthRule> newRules = new ArrayList<>(rules);
		Class<? extends IBaseResource> valueSetClass;
		switch (fhirVersionName) {
			case "R4":
				valueSetClass = org.hl7.fhir.r4.model.ValueSet.class;
				break;
			case "R4B":
				valueSetClass = org.hl7.fhir.r4b.model.ValueSet.class;
				break;
			case "R5":
				valueSetClass = org.hl7.fhir.r5.model.ValueSet.class;
				break;
			default:
				newRules.addAll(new RuleBuilder().denyAll().build());
				return newRules;
		}
		newRules.addAll(new RuleBuilder()
			.allow().read().resourcesOfType("ValueSet").withAnyId().andThen()
			.allow().operation().withAnyName().onType(valueSetClass).andAllowAllResponses().andThen()
			.build()
		);
		return newRules;
	}

	private List<IAuthRule> addAllowReadAndAllOperationOfConceptMap(List<IAuthRule> rules, String fhirVersionName) {
		List<IAuthRule> newRules = new ArrayList<>(rules);
		Class<? extends IBaseResource> conceptMapClass;
		switch (fhirVersionName) {
			case "R4":
				conceptMapClass = org.hl7.fhir.r4.model.ConceptMap.class;
				break;
			case "R4B":
				conceptMapClass = org.hl7.fhir.r4b.model.ConceptMap.class;
				break;
			case "R5":
				conceptMapClass = org.hl7.fhir.r5.model.ConceptMap.class;
				break;
			default:
				newRules.addAll(new RuleBuilder().denyAll().build());
				return newRules;
		}
		newRules.addAll(new RuleBuilder()
			.allow().read().resourcesOfType("ConceptMap").withAnyId().andThen()
			.allow().operation().withAnyName().onType(conceptMapClass).andAllowAllResponses().andThen()
			.build()
		);
		return newRules;
	}

	private boolean validateToken(String token) {
		String jwksUrl = this.appProperties.getOauth2().getJwks_uri();
		String issuer = this.appProperties.getOauth2().getIssuer();
		try {
			// Create a JwkProvider for the JWKS URL
			JwkProvider provider = new JwkProviderBuilder(jwksUrl)
				.cached(10, 24, TimeUnit.HOURS) // Cache up to 10 keys for 24 hours
				.rateLimited(10, 1, TimeUnit.MINUTES) // Allow up to 10 requests per minute
				.build();

			Algorithm algorithm = getAlgorithm(provider);

			// Prepare the verifier with the issuer and audience if necessary
			JWTVerifier verifier = JWT.require(algorithm)
				.withIssuer(issuer)
				.build();

			// Verify the token
			verifier.verify(token);

			// If no exception is thrown, the token is valid
			return true;
		} catch (Exception e) {
			// Log or handle the exception as needed
			logger.error(e.toString());
			return false;
		}
	}

	@NotNull
	private static Algorithm getAlgorithm(JwkProvider provider) {
		RSAKeyProvider keyProvider = new RSAKeyProvider() {
			@Override
			public RSAPublicKey getPublicKeyById(String keyId) {
				try {
					return (RSAPublicKey) provider.get(keyId).getPublicKey();
				} catch (Exception e) {
					throw new RuntimeException("Could not fetch the public key from JWKS", e);
				}
			}

			@Override
			public RSAPrivateKey getPrivateKey() {
				return null; // Not used for token verification
			}

			@Override
			public String getPrivateKeyId() {
				return null; // Not used for token verification
			}
		};

		// Prepare the algorithm with the key provider
		return Algorithm.RSA256(keyProvider);
	}
}