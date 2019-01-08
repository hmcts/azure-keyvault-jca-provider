package uk.gov.hmcts.reform.security.keyvault;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.common.FileSource;
import com.github.tomakehurst.wiremock.extension.Parameters;
import com.github.tomakehurst.wiremock.extension.ResponseDefinitionTransformer;
import com.github.tomakehurst.wiremock.http.Request;
import com.github.tomakehurst.wiremock.http.ResponseDefinition;
import com.google.common.collect.ImmutableMap;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.models.SecretBundle;
import com.microsoft.rest.credentials.ServiceClientCredentials;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import uk.gov.hmcts.reform.security.keyvault.credential.AccessTokenKeyVaultCredential;

import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.configureFor;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class AccessTokenKeyVaultCredentialTest {

    private static final int DUMMY_VAULT_SERVER_PORT = 9999;

    private static final String BASE_URL = "http://localhost:" + DUMMY_VAULT_SERVER_PORT + "/test";

    private static final String VAULT_MSI_URL = "http://localhost:" + DUMMY_VAULT_SERVER_PORT
        + "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net";

    @Mock
    private KeyVaultService keyVaultService;

    private static WireMockServer wireMockServer;

    protected static final Map<String, String> VAULT_PROPERTIES = ImmutableMap.of(
        "test-owner-username", "phil.space",
        "test-owner-password", "PasswOrd",
        "web-admin-client-secret", "secret",
        "BINDPASSWD", "ABCDE",
        "appinsights-instrumentationkey", "ABCDE12345");

    private static final String TOKEN_RESPONSE = "{"
        + "\"access_token\": \"eyJ0eXAiOiJKV1...hQ5J4_hoQ\",\n"
        + "\"client_id\": \"9b48de17-5f97-45ea-b4e8-912f60c95ba3\",\n"
        + "\"expires_in\": \"28800\",\n"
        + "\"expires_on\": \"1545076836\",\n"
        + "\"ext_expires_in\": \"28800\",\n"
        + "\"not_before\": \"1545047736\",\n"
        + "\"resource\": \"https://vault.azure.net\",\n"
        + "\"token_type\": \"Bearer\"\n"
        + "}";

    private static final String SECRET_RESPONSE_TEMPLATE = "{\"value\":\"%s\",\n"
        + "\"id\":\"https://test.vault.azure.net/secrets/%s/5f5b24471cca47f99cdd3204d41372d2\",\n"
        + "\"attributes\":"
        + "{\"enabled\":true,\"created\":1541609008,\"updated\":1541609008,\"recoveryLevel\":\"Purgeable\"},\n"
        + "\"tags\":{\"file-encoding\":\"utf-8\"}}";

    @Before
    public void setUp() {
        System.setProperty(KeyVaultConfig.VAULT_BASE_URL, BASE_URL);

        wireMockServer = new WireMockServer(options()
            .port(DUMMY_VAULT_SERVER_PORT)
            .extensions(ExampleTransformer.class));
        wireMockServer.start();

        configureFor("localhost", DUMMY_VAULT_SERVER_PORT);
        stubFor(get(urlPathMatching("/metadata/identity/oauth2/.*"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(TOKEN_RESPONSE)));

        stubFor(get(urlPathMatching("/test/.*"))
            .willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withTransformers("secret-response-transformer")));
    }

    @After
    public void shutdown() {
        wireMockServer.stop();
    }

    /**
     * @verifies select correct client based on system properties
     * @see KeyVaultService#getClient(KeyVaultConfig keyVaultConfig)
     */
    @Test
    public void getClient_shouldCreateAccessTokenClientAndHandleDummyServerResponses() {
        System.setProperty(KeyVaultConfig.VAULT_MSI_URL, VAULT_MSI_URL);
        System.setProperty(KeyVaultConfig.VAULT_ERROR_MAX_RETRIES, "2");
        System.setProperty(KeyVaultConfig.VAULT_ERROR_RETRY_INTERVAL_MILLIS, "30");

        KeyVaultConfig config = new KeyVaultConfig();
        assertEquals(VAULT_MSI_URL, config.getVaultMsiUrl());

        when(keyVaultService.getClient(config)).thenCallRealMethod();

        KeyVaultClient client = keyVaultService.getClient(config);
        ServiceClientCredentials credentials = client.restClient().credentials();

        assertTrue(credentials instanceof AccessTokenKeyVaultCredential);

        SecretBundle usernameBundle = client.getSecret(BASE_URL, "test-owner-username");
        String usernameValue = usernameBundle.value();
        assertEquals("phil.space", usernameValue);

        SecretBundle bindPasswordBundle = client.getSecret(BASE_URL, "BINDPASSWD");
        String bindPasswordValue = bindPasswordBundle.value();
        assertEquals("ABCDE", bindPasswordValue);
    }

    public static class ExampleTransformer extends ResponseDefinitionTransformer {

        @Override
        public ResponseDefinition transform(Request request, ResponseDefinition responseDefinition, FileSource files,
                                            Parameters parameters) {

            return new ResponseDefinitionBuilder()
                .withHeader("Content-Type", "application/json")
                .withStatus(200)
                .withBody(generateResponse(request.getUrl()))
                .build();
        }

        private static String generateResponse(String path) {
            for (String key : VAULT_PROPERTIES.keySet()) {
                if (path.contains(key)) {
                    return String.format(SECRET_RESPONSE_TEMPLATE, VAULT_PROPERTIES.get(key), key);
                }
            }

            return String.format(SECRET_RESPONSE_TEMPLATE, "--", "--");
        }

        @Override
        public String getName() {
            return "secret-response-transformer";
        }

        @Override
        public boolean applyGlobally() {
            return false;
        }
    }
}