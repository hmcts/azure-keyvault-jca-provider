package uk.gov.hmcts.reform.vault.credential;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;
import reactor.core.publisher.Mono;

public class AccessTokenKeyVaultCredential implements TokenCredential {

//    private static final String METADATA_HEADER = "Metadata";
//
//    private final LoadingCache<String, String> accessTokenCacheLoader;
//
//    private static final TokenResponseHandler tokenResponseHandler = new TokenResponseHandler();
//
//    public AccessTokenKeyVaultCredential(String tokenEndpoint, int maxRetries, int retryInterval) {
//        super(AzureEnvironment.AZURE, null);
//        accessTokenCacheLoader = CacheBuilder.newBuilder()
//            .expireAfterWrite(1, TimeUnit.HOURS)
//            .build(new AccessTokenKeyVaultCredential
//                .AccessTokenCacheLoader(tokenEndpoint, maxRetries, retryInterval));
//    }
//
//    @Override
//    public String getToken(String resource) {
//        return accessTokenCacheLoader.getUnchecked(resource);
//    }
//
//    public void invalidateTokenCache() {
//        this.accessTokenCacheLoader.invalidateAll();
//    }
//
//    static final class AccessTokenCacheLoader extends CacheLoader<String, String> {
//
//        private final HttpClient httpClient;
//
//        private final HttpUriRequest request;
//
//        AccessTokenCacheLoader(String tokenEndpoint, int maxRetries, int retryInterval) {
//            this.request = RequestBuilder.get()
//                .setUri(tokenEndpoint)
//                .setHeader(METADATA_HEADER, Boolean.TRUE.toString())
//                .build();
//
//            this.httpClient = HttpClientBuilder.create().setServiceUnavailableRetryStrategy(
//                new ServiceUnavailableRetryStrategy() {
//                    @Override
//                    public boolean retryRequest(final HttpResponse response,
//                                                final int executionCount, final HttpContext context) {
//                        int statusCode = response.getStatusLine().getStatusCode();
//                        return statusCode >= HttpStatus.SC_INTERNAL_SERVER_ERROR
//                            && executionCount < maxRetries;
//                    }
//
//                    @Override
//                    public long getRetryInterval() {
//                        return retryInterval;
//                    }
//                }).build();
//
//        }
//
//        @Override
//        public String load(String resource) throws Exception {
//            String key = httpClient.execute(request, tokenResponseHandler);
//            if (key == null) {
//                throw new NullPointerException();
//            }
//            return key;
//        }
//    }
//
    @Override
    public Mono<AccessToken> getToken(TokenRequestContext request) {
        return null;
    }

    @Override
    public AccessToken getTokenSync(TokenRequestContext request) {
        return TokenCredential.super.getTokenSync(request);
    }
}
