package ca.uhn.fhir.jpa.starter.interceptor;

import ca.uhn.fhir.jpa.starter.interceptor.model.OPAResponse;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;
import org.json.JSONObject;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestTemplate;

import java.util.List;

public class CortexAuthorizationInterceptor extends AuthorizationInterceptor {

	@Override
	public List<IAuthRule> buildRuleList(RequestDetails theRequestDetails) {

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

		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		JSONObject opaJsonObject = new JSONObject();
		JSONObject opaInputJsonObject = new JSONObject();
		opaInputJsonObject.put("token", token);
		opaJsonObject.put("input", opaInputJsonObject);
		HttpEntity<String> request = new HttpEntity<String>(opaJsonObject.toString(), headers);

		RestTemplate restTemplate = new RestTemplate();
		OPAResponse check = restTemplate.postForObject("http://localhost:8181/v1/data/cortex/fhir/allow", request, OPAResponse.class);

		if (Boolean.TRUE.equals(check.result)) {
			return new RuleBuilder().allowAll().build();
		}

		return new RuleBuilder().denyAll().build();
	}
}
