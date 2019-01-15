package uk.gov.hmcts.reform.security.keyvault;

import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.rest.credentials.ServiceClientCredentials;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;
import uk.gov.hmcts.reform.vault.config.KeyVaultConfig;
import uk.gov.hmcts.reform.vault.credential.AccessTokenKeyVaultCredential;
import uk.gov.hmcts.reform.vault.credential.ClientSecretKeyVaultCredential;

import java.security.ProviderException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(MockitoJUnitRunner.class)
public class KeyVaultServiceClientTest {

    private static final String BASE_URL = "BASE_URL";

    @Before
    public void setUp() {
    }

    /**
     * @verifies select correct client based on system properties
     * @see KeyVaultService#getClient()
     */
    @Test
    public void getClient_shouldCreateAccessTokenClient() {
        KeyVaultConfig config = new SystemPropertyKeyVaultConfigBuilder().build();
        config.setVaultBaseUrl(BASE_URL);
        config.setVaultClientId("");
        config.setVaultClientKey("");
        config.setVaultMsiUrl("MSI_URL");
        config.setVaultErrorMaxRetries(2);
        config.setVaultErrorRetryIntervalMillis(30);

        assertEquals("MSI_URL", config.getVaultMsiUrl());

        KeyVaultService keyVaultService = new KeyVaultService(config);
        KeyVaultClient client = keyVaultService.getClient();
        ServiceClientCredentials credentials = client.restClient().credentials();

        assertTrue(credentials instanceof AccessTokenKeyVaultCredential);
    }

    /**
     * @verifies select correct client based on system properties
     * @see KeyVaultService#getClient()
     */
    @Test
    public void getClient_shouldCreateClientSecretClient() {
        KeyVaultConfig config = new SystemPropertyKeyVaultConfigBuilder().build();
        config.setVaultBaseUrl(BASE_URL);
        config.setVaultClientId("CLIENT_ID");
        config.setVaultClientKey("CLIENT_KEY");

        assertEquals("CLIENT_ID", config.getVaultClientId());
        assertEquals("CLIENT_KEY", config.getVaultClientKey());

        KeyVaultService keyVaultService = new KeyVaultService(config);
        KeyVaultClient client = keyVaultService.getClient();
        ServiceClientCredentials credentials = client.restClient().credentials();

        assertTrue(credentials instanceof ClientSecretKeyVaultCredential);
    }

    /**
     * @verifies select correct client based on system properties
     * @see KeyVaultService#getClient()
     */
    @Test(expected = ProviderException.class)
    public void getClient_shouldCreateClientSecretClientAndThrowErrorWithNoAuthorization() {
        KeyVaultConfig config = new SystemPropertyKeyVaultConfigBuilder().build();
        config.setVaultBaseUrl(BASE_URL);
        config.setVaultClientId("CLIENT_ID");
        config.setVaultClientKey("CLIENT_KEY");

        assertEquals("CLIENT_ID", config.getVaultClientId());
        assertEquals("CLIENT_KEY", config.getVaultClientKey());

        KeyVaultService keyVaultService = new KeyVaultService(config);
        KeyVaultClient client = keyVaultService.getClient();
        ServiceClientCredentials credentials = client.restClient().credentials();

        assertTrue(credentials instanceof ClientSecretKeyVaultCredential);

        ClientSecretKeyVaultCredential creds = (ClientSecretKeyVaultCredential)credentials;
        creds.doAuthenticate("", "", "");
    }

    @Test
    public void testKeyVaultConfigEquals_Symmetric() {
        KeyVaultConfig config1 = new SystemPropertyKeyVaultConfigBuilder().build();
        config1.setVaultClientId("CLIENT_ID");
        config1.setVaultClientKey("CLIENT_KEY");
        config1.setVaultMsiUrl("MSI_URL");
        config1.setVaultErrorMaxRetries(1);
        config1.setVaultErrorRetryIntervalMillis(10);
        config1.setVaultBaseUrl("BASE_URL");

        KeyVaultConfig config2 = new SystemPropertyKeyVaultConfigBuilder().build();
        config2.setVaultClientId("CLIENT_ID");
        config2.setVaultClientKey("CLIENT_KEY");
        config2.setVaultMsiUrl("MSI_URL");
        config2.setVaultErrorMaxRetries(1);
        config2.setVaultErrorRetryIntervalMillis(10);
        config2.setVaultBaseUrl("BASE_URL");

        assertTrue(config1.equals(config2) && config2.equals(config1));
        assertTrue(config1.hashCode() == config2.hashCode());
    }
}
