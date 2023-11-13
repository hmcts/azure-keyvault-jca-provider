package uk.gov.hmcts.reform.vault.credential;

public class TokenResponseHandler {
//public class TokenResponseHandler implements ResponseHandler<String> {

//    private static final String ACCESS_TOKEN_KEY = "access_token";
//
//    private static final ObjectMapper mapper = new ObjectMapper();
//
//    @Override
//    public String handleResponse(HttpResponse response) throws IOException {
//        StatusLine statusLine = response.getStatusLine();
//        if (statusLine.getStatusCode() != HttpStatus.SC_OK) {
//            throw new HttpResponseException(statusLine.getStatusCode(), statusLine.getReasonPhrase());
//        }
//
//        HttpEntity entity = response.getEntity();
//        String json = EntityUtils.toString(entity, StandardCharsets.UTF_8);
//
//        ObjectNode node = mapper.readValue(json, ObjectNode.class);
//        if (node.has(ACCESS_TOKEN_KEY)) {
//            return node.get(ACCESS_TOKEN_KEY).asText();
//        }
//
//        throw new HttpResponseException(HttpStatus.SC_INTERNAL_SERVER_ERROR,
//            "No access_token parameter present in response");
//    }
}
