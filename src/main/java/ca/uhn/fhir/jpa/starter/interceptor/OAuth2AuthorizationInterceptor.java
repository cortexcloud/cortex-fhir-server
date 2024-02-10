package ca.uhn.fhir.jpa.starter.interceptor;

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
import com.auth0.jwt.interfaces.RSAKeyProvider;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.TimeUnit;

import java.util.List;

@Component
public class OAuth2AuthorizationInterceptor extends AuthorizationInterceptor {

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
			return new RuleBuilder().allowAll().build();
		}
		return new RuleBuilder().denyAll().build();
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
			e.printStackTrace();
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