package uk.gov.hmcts.reform.security.keyvault.credential;

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

import java.io.IOException;

public class AccessTokenKeyVaultCredential extends AzureTokenCredentials {

    private static final String METADATA_HEADER = "Metadata";

    private final String tokenEndpoint;

    private final HttpClient httpClient;

    private static final TokenResponseHandler tokenResponseHandler = new TokenResponseHandler();

    public AccessTokenKeyVaultCredential(String tokenEndpoint, int maxRetries, int retryInterval) {
        super(AzureEnvironment.AZURE, null);
        this.tokenEndpoint = tokenEndpoint;
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
    public String getToken(String resource) throws IOException {

        HttpUriRequest request = RequestBuilder.get()
                .setUri(tokenEndpoint)
                .setHeader(METADATA_HEADER, Boolean.TRUE.toString())
                .build();

        return httpClient.execute(request, tokenResponseHandler);
    }
}
