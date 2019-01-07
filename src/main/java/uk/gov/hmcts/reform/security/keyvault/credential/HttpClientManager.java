package uk.gov.hmcts.reform.security.keyvault.credential;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ServiceUnavailableRetryStrategy;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.protocol.HttpContext;

public class HttpClientManager {
    private static volatile HttpClient instance;

    private HttpClientManager() {
    }

    public static HttpClient getInstance(int maxRetries, int retryInterval) {
        if (instance == null) {
            synchronized (TokenResponseHandler.class) {
                if (instance == null) {
                    instance = HttpClientBuilder.create().setServiceUnavailableRetryStrategy(
                            new ServiceUnavailableRetryStrategy() {
                                @Override
                                public boolean retryRequest(final HttpResponse response,
                                                            final int executionCount,
                                                            final HttpContext context) {
                                    int statusCode = response.getStatusLine().getStatusCode();
                                    return statusCode == 500 && executionCount < maxRetries;
                                }

                                @Override
                                public long getRetryInterval() {
                                    return retryInterval;
                                }
                            }).build();
                }
            }
        }

        return instance;
    }
}
