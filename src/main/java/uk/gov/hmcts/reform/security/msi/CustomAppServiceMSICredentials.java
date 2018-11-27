package uk.gov.hmcts.reform.security.msi;

import com.microsoft.azure.AzureEnvironment;
import com.microsoft.azure.credentials.AzureTokenCredentials;
import com.microsoft.azure.serializer.AzureJacksonAdapter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class CustomAppServiceMSICredentials extends AzureTokenCredentials {

    private static final String MSI_TOKEN_URL = "http://169.254.169.254/metadata/identity/oauth2/token";
    private static final String MSI_QUERY_STRING = "?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net";
    private static final String MSI_KEYVAULT_TOKEN_URL = MSI_TOKEN_URL + MSI_QUERY_STRING;
    private static final String HTTP_METHOD_GET = "GET";
    private static final String REQUEST_HEADER_METADATA = "Metadata";
    private static final String REQUEST_HEADER_METADATA_VALUE_TRUE = "true";


    public CustomAppServiceMSICredentials(AzureEnvironment environment) {
        super(environment, null);
    }

    @Override
    public String getToken(String resource) throws IOException {

        URL url = new URL(MSI_KEYVAULT_TOKEN_URL);
        HttpURLConnection connection = null;

        try {
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod(HTTP_METHOD_GET);
            connection.setRequestProperty(REQUEST_HEADER_METADATA, REQUEST_HEADER_METADATA_VALUE_TRUE);
            connection.connect();

            InputStream stream = connection.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8), 100);
            String result = reader.readLine();

            AzureJacksonAdapter adapter = new AzureJacksonAdapter();
            AccessTokenRespHolder tokenRespHolder = adapter.deserialize(result, AccessTokenRespHolder.class);

            return tokenRespHolder.getAccessToken();

        } catch (Exception e) {
            throw e;

        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }

    }
}
