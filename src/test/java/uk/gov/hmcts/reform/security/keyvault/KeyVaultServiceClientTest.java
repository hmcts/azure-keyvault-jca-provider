package uk.gov.hmcts.reform.security.keyvault;

import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.rest.credentials.ServiceClientCredentials;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import uk.gov.hmcts.reform.security.keyvault.credential.AccessTokenKeyVaultCredential;
import uk.gov.hmcts.reform.security.keyvault.credential.ClientSecretKeyVaultCredential;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class KeyVaultServiceClientTest {

    private static final String BASE_URL = "BASE_URL";

    @Mock
    private KeyVaultService keyVaultService;

    @Before
    public void setUp() {
        System.setProperty(KeyVaultConfig.VAULT_BASE_URL, BASE_URL);
    }

    /**
     * @verifies select correct client based on system properties
     * @see KeyVaultService#getClient(KeyVaultConfig keyVaultConfig)
     */
    @Test
    public void getClient_shouldCreateAccessTokenClient() {
        System.setProperty(KeyVaultConfig.VAULT_CLIENT_ID, "");
        System.setProperty(KeyVaultConfig.VAULT_CLIENT_KEY, "");
        System.setProperty(KeyVaultConfig.VAULT_MSI_URL, "MSI_URL");
        System.setProperty(KeyVaultConfig.VAULT_ERROR_MAX_RETRIES, "2");
        System.setProperty(KeyVaultConfig.VAULT_ERROR_RETRY_INTERVAL_MILLIS, "30");

        KeyVaultConfig config = new KeyVaultConfig();
        assertEquals("MSI_URL", config.getVaultMsiUrl());

        when(keyVaultService.getClient(config)).thenCallRealMethod();

        KeyVaultClient client = keyVaultService.getClient(config);
        ServiceClientCredentials credentials = client.restClient().credentials();

        assertTrue(credentials instanceof AccessTokenKeyVaultCredential);
    }

    /**
     * @verifies select correct client based on system properties
     * @see KeyVaultService#getClient(KeyVaultConfig keyVaultConfig)
     */
    @Test
    public void getClient_shouldCreateClientSecretClient() {
        System.setProperty(KeyVaultConfig.VAULT_CLIENT_ID, "CLIENT_ID");
        System.setProperty(KeyVaultConfig.VAULT_CLIENT_KEY, "CLIENT_KEY");

        KeyVaultConfig config = new KeyVaultConfig();
        assertEquals("CLIENT_ID", config.getVaultClientId());
        assertEquals("CLIENT_KEY", config.getVaultClientKey());

        when(keyVaultService.getClient(config)).thenCallRealMethod();

        KeyVaultClient client = keyVaultService.getClient(config);
        ServiceClientCredentials credentials = client.restClient().credentials();

        assertTrue(credentials instanceof ClientSecretKeyVaultCredential);
    }

    /**
     * @verifies select correct client based on system properties
     * @see KeyVaultService#getClient(KeyVaultConfig keyVaultConfig)
     */
    @Test
    public void getClient_shouldCreateClientSecretClient2() {
        System.setProperty(KeyVaultConfig.VAULT_CLIENT_ID, "CLIENT_ID");
        System.setProperty(KeyVaultConfig.VAULT_CLIENT_KEY, "CLIENT_KEY");

        KeyVaultConfig config = new KeyVaultConfig();
        assertEquals("CLIENT_ID", config.getVaultClientId());
        assertEquals("CLIENT_KEY", config.getVaultClientKey());

        when(keyVaultService.getClient(config)).thenCallRealMethod();

        KeyVaultClient client = keyVaultService.getClient(config);
        ServiceClientCredentials credentials = client.restClient().credentials();

        assertTrue(credentials instanceof ClientSecretKeyVaultCredential);
    }

    @Test
    public void testKeyVaultConfigEquals_Symmetric() {
        KeyVaultConfig config1 = new KeyVaultConfig();
        config1.setVaultClientId("CLIENT_ID");
        config1.setVaultClientKey("CLIENT_KEY");
        config1.setVaultMsiUrl("MSI_URL");
        config1.setVaultErrorMaxRetries(1);
        config1.setVaultErrorRetryIntervalMillis(10);
        config1.setVaultBaseUrl("BASE_URL");

        KeyVaultConfig config2 = new KeyVaultConfig();
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
