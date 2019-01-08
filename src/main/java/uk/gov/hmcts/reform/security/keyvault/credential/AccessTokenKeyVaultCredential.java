package uk.gov.hmcts.reform.security.keyvault.credential;

import com.microsoft.azure.AzureEnvironment;
import com.microsoft.azure.credentials.AzureTokenCredentials;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ServiceUnavailableRetryStrategy;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.protocol.HttpContext;

import java.io.IOException;

import static uk.gov.hmcts.reform.security.keyvault.KeyVaultConfig.VAULT_ERROR_MAX_RETRIES;
import static uk.gov.hmcts.reform.security.keyvault.KeyVaultConfig.VAULT_ERROR_RETRY_INTERVAL_MILLIS;

public class AccessTokenKeyVaultCredential extends AzureTokenCredentials {

    private static final String METADATA_HEADER = "Metadata";

    private final String tokenEndpoint;

    private static final HttpClient HTTP_CLIENT = HttpClientBuilder.create().setServiceUnavailableRetryStrategy(
        new ServiceUnavailableRetryStrategy() {
            @Override
            public boolean retryRequest(final HttpResponse response,
                                        final int executionCount, final HttpContext context) {
                int statusCode = response.getStatusLine().getStatusCode();
                return statusCode == 500
                    && executionCount < Integer.valueOf(System.getProperty(VAULT_ERROR_MAX_RETRIES));
            }

            @Override
            public long getRetryInterval() {
                return Integer.valueOf(System.getProperty(VAULT_ERROR_RETRY_INTERVAL_MILLIS));
            }
        }).build();

    public AccessTokenKeyVaultCredential(String tokenEndpoint) {
        super(AzureEnvironment.AZURE, null);
        this.tokenEndpoint = tokenEndpoint;
    }

    @Override
    public String getToken(String resource) throws IOException {

        HttpUriRequest request = RequestBuilder.get()
                .setUri(tokenEndpoint)
                .setHeader(METADATA_HEADER, Boolean.TRUE.toString())
                .build();

        return HTTP_CLIENT.execute(request, TokenResponseHandler.getInstance());
    }
}
