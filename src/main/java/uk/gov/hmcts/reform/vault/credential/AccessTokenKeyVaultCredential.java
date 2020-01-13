package uk.gov.hmcts.reform.vault.credential;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.microsoft.azure.AzureEnvironment;
import com.microsoft.azure.credentials.AzureTokenCredentials;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ServiceUnavailableRetryStrategy;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.protocol.HttpContext;

import java.util.concurrent.TimeUnit;

public class AccessTokenKeyVaultCredential extends AzureTokenCredentials {

    private static final String METADATA_HEADER = "Metadata";

    private final LoadingCache<String, String> accessTokenCacheLoader;

    private static final TokenResponseHandler tokenResponseHandler = new TokenResponseHandler();

    public AccessTokenKeyVaultCredential(String tokenEndpoint, int maxRetries, int retryInterval) {
        super(AzureEnvironment.AZURE, null);
        accessTokenCacheLoader = CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)
            .build(new AccessTokenKeyVaultCredential
                .AccessTokenCacheLoader(tokenEndpoint, maxRetries, retryInterval));
    }

    @Override
    public String getToken(String resource) {
        return accessTokenCacheLoader.getUnchecked(resource);
    }

    public void invalidateTokenCache() {
        this.accessTokenCacheLoader.invalidateAll();
    }

    static final class AccessTokenCacheLoader extends CacheLoader<String, String> {

        private final HttpClient httpClient;

        private final HttpUriRequest request;

        AccessTokenCacheLoader(String tokenEndpoint, int maxRetries, int retryInterval) {
            this.request = RequestBuilder.get()
                .setUri(tokenEndpoint)
                .setHeader(METADATA_HEADER, Boolean.TRUE.toString())
                .build();

            this.httpClient = HttpClientBuilder.create().setServiceUnavailableRetryStrategy(
                new ServiceUnavailableRetryStrategy() {
                    @Override
                    public boolean retryRequest(final HttpResponse response,
                                                final int executionCount, final HttpContext context) {
                        int statusCode = response.getStatusLine().getStatusCode();
                        return statusCode >= HttpStatus.SC_INTERNAL_SERVER_ERROR
                            && executionCount < maxRetries;
                    }

                    @Override
                    public long getRetryInterval() {
                        return retryInterval;
                    }
                }).build();

        }

        @Override
        public String load(String resource) throws Exception {
            String key = httpClient.execute(request, tokenResponseHandler);
            if (key == null) {
                throw new NullPointerException();
            }
            return key;
        }
    }
}
