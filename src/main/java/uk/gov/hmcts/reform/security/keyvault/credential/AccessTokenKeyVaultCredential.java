package uk.gov.hmcts.reform.security.keyvault.credential;

import com.microsoft.azure.AzureEnvironment;
import com.microsoft.azure.credentials.AzureTokenCredentials;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;

import java.io.IOException;

public class AccessTokenKeyVaultCredential extends AzureTokenCredentials {

    private static final String METADATA_HEADER = "Metadata";

    private final String tokenEndpoint;

    private final int maxRetries;

    private final int retryInterval;

    public AccessTokenKeyVaultCredential(String tokenEndpoint, int  maxRetries, int retryInterval) {
        super(AzureEnvironment.AZURE, null);
        this.tokenEndpoint = tokenEndpoint;
        this.maxRetries = maxRetries;
        this.retryInterval = retryInterval;
    }

    @Override
    public String getToken(String resource) throws IOException {

        HttpUriRequest request = RequestBuilder.get()
                .setUri(tokenEndpoint)
                .setHeader(METADATA_HEADER, Boolean.TRUE.toString())
                .build();

        return HttpClientManager.getInstance(maxRetries, retryInterval).execute(request,
            TokenResponseHandler.getInstance());
    }
}
