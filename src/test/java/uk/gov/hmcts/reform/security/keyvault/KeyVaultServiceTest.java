package uk.gov.hmcts.reform.security.keyvault;

import com.google.common.cache.CacheBuilder;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.models.CertificateBundle;
import com.microsoft.azure.keyvault.models.KeyBundle;
import com.microsoft.azure.keyvault.webkey.JsonWebKeySignatureAlgorithm;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.junit.Assert.assertEquals;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@RunWith(MockitoJUnitRunner.class)
public class KeyVaultServiceTest {

    private static final String ALIAS = "ALIAS";

    private static final String BASE_URL = "BASE_URL";

    private static final String KEY_IDENTIFIER = "KEY_ID";

    @BeforeClass
    public static void beforeClass() {
        System.setProperty(KeyVaultConfig.VAULT_BASE_URL, BASE_URL);
    }

    @Mock
    private KeyVaultClient vaultClient;

    private KeyVaultService keyVaultService;

    @Before
    public void setUp() {
        keyVaultService = new KeyVaultService(vaultClient,
            CacheBuilder.newBuilder().build(new KeyVaultService.KeyByAliasCacheLoader(BASE_URL, vaultClient)),
            CacheBuilder.newBuilder().build(new KeyVaultService.KeyByIdentifierCacheLoader(vaultClient)),
            CacheBuilder.newBuilder().build(new KeyVaultService.CertificateByAliasCacheLoader(BASE_URL, vaultClient)));
    }

    /**
     * @verifies call delegate
     * @see KeyVaultService#getKeyByAlias(String)
     */
    @Test
    public void getKeyByAlias_shouldCallDelegate() {
        KeyBundle mock = mock(KeyBundle.class);
        given(vaultClient.getKey(BASE_URL, ALIAS)).willReturn(mock);

        KeyBundle keyBundle = keyVaultService.getKeyByAlias(ALIAS);

        verify(vaultClient).getKey(BASE_URL, ALIAS);
        assertEquals(mock, keyBundle);
    }

    /**
     * @verifies call delegate
     * @see KeyVaultService#getKeyByIdentifier(String)
     */
    @Test
    public void getKeyByIdentifier_shouldCallDelegate() {
        KeyBundle mock = mock(KeyBundle.class);
        given(vaultClient.getKey(KEY_IDENTIFIER)).willReturn(mock);

        KeyBundle keyBundle = keyVaultService.getKeyByIdentifier(KEY_IDENTIFIER);

        verify(vaultClient).getKey(KEY_IDENTIFIER);
        assertEquals(mock, keyBundle);
    }

    /**
     * @verifies call delegate
     * @see KeyVaultService#getCertificateByAlias(String)
     */
    @Test
    public void getCertificateByAlias_shouldCallDelegate() {
        CertificateBundle mock = mock(CertificateBundle.class);
        given(vaultClient.getCertificate(BASE_URL, ALIAS)).willReturn(mock);

        CertificateBundle certificateBundle = keyVaultService.getCertificateByAlias(ALIAS);

        verify(vaultClient).getCertificate(BASE_URL, ALIAS);
        assertEquals(mock, certificateBundle);
    }

    /**
     * @verifies call delegate
     * @see KeyVaultService#sign(String, com.microsoft.azure.keyvault.webkey.JsonWebKeySignatureAlgorithm, byte[])
     */
    @Test
    public void sign_shouldCallDelegate() {
        keyVaultService.sign(KEY_IDENTIFIER, JsonWebKeySignatureAlgorithm.RS256, new byte[0]);
        verify(vaultClient).sign(KEY_IDENTIFIER, JsonWebKeySignatureAlgorithm.RS256, new byte[0]);
    }
}
