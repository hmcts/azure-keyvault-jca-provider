package uk.gov.hmcts.reform.security.keyvault.credential;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class TokenResponseHandler implements ResponseHandler<String> {

    private static final String ACCESS_TOKEN_KEY = "access_token";

    private static volatile TokenResponseHandler instance;

    private static final ObjectMapper mapper = new ObjectMapper();

    @Override
    public String handleResponse(HttpResponse response) throws IOException {
        StatusLine statusLine = response.getStatusLine();
        if (statusLine.getStatusCode() != HttpStatus.SC_OK) {
            throw new HttpResponseException(statusLine.getStatusCode(), statusLine.getReasonPhrase());
        }

        HttpEntity entity = response.getEntity();
        String json = EntityUtils.toString(entity, StandardCharsets.UTF_8);

        ObjectNode node = mapper.readValue(json, ObjectNode.class);
        if (node.has(ACCESS_TOKEN_KEY)) {
            return node.get(ACCESS_TOKEN_KEY).asText();
        }

        throw new HttpResponseException(statusLine.getStatusCode(), "No access_token parameter present in response");
    }
}
