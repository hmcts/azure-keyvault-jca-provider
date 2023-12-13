package uk.gov.hmcts.reform.security.keyvault;

import com.azure.core.util.polling.PollResponse;
import com.azure.core.util.polling.SyncPoller;
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificateWithPolicy;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.DeletedSecret;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import uk.gov.hmcts.reform.vault.credential.CachedDefaultAzureCredential;

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@RunWith(MockitoJUnitRunner.class)
public class KeyVaultServiceTest {

    private static final String ALIAS = "ALIAS";

    private static final String BASE_URL = "https://www.BASE_URL.com";

    private static final String KEY_IDENTIFIER = "KEY_ID";

    @Mock
    private CachedDefaultAzureCredential credential;

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private KeyClient keyClient;

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private SecretClient secretClient;

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private CertificateClient certificateClient;

    private KeyVaultService keyVaultService;

    @Before
    public void setUp() {
        System.setProperty(SystemPropertyKeyVaultConfigBuilder.VAULT_BASE_URL, BASE_URL);
        KeyVaultService.ClientHolder holder = new KeyVaultService
            .ClientHolder(secretClient, keyClient, certificateClient);
        keyVaultService = new KeyVaultService(new SystemPropertyKeyVaultConfigBuilder().build(), holder);
    }

    /**
     * @verifies call delegate
     * @see KeyVaultService#getKeyByAlias(String)
     */
    @Test
    public void getKeyByAlias_shouldCallDelegate() {
        KeyVaultKey mock = mock(KeyVaultKey.class);
        given(keyClient.getKey(ALIAS)).willReturn(mock);

        KeyVaultKey keyBundle = keyVaultService.getKeyByAlias(ALIAS);

        verify(keyClient).getKey(ALIAS);
        assertEquals(mock, keyBundle);
    }

    /**
     * @verifies call delegate
     * @see KeyVaultService#getCertificateByAlias(String)
     */
    @Test
    public void getCertificateByAlias_shouldCallDelegate() {
        KeyVaultCertificateWithPolicy mock = mock(KeyVaultCertificateWithPolicy.class);
        given(certificateClient.getCertificate(ALIAS)).willReturn(mock);

        KeyVaultCertificateWithPolicy certificateBundle = keyVaultService.getCertificateByAlias(ALIAS);

        verify(certificateClient).getCertificate(ALIAS);
        assertEquals(mock, certificateBundle);
    }

    /**
     * @verifies call delegate if key is SecretKey
     * @see KeyVaultService#setKeyByAlias(String, java.security.Key)
     */
    @Test
    public void setKeyByAlias_shouldCallDelegateIfKeyIsSecretKey() throws KeyStoreException {
        SecretKey mockKey = new KeyStore
            .SecretKeyEntry(new SecretKeySpec("SEKRET_KEY".getBytes(), "RAW")).getSecretKey();
        KeyVaultSecret bundle = mock(KeyVaultSecret.class);

        given(secretClient.setSecret(any(KeyVaultSecret.class))).willReturn(bundle);

        given(secretClient.getSecret(ALIAS)).willReturn(bundle);

        KeyVaultSecret resultBundle = keyVaultService.setKeyByAlias(ALIAS, mockKey);

        verify(secretClient).setSecret(any(KeyVaultSecret.class));
        assertEquals(bundle, resultBundle);
    }

    /**
     * @verifies throw exception if key is unsupported
     * @see KeyVaultService#setKeyByAlias(String, java.security.Key)
     */
    @Test(expected = UnsupportedOperationException.class)
    public void setKeyByAlias_shouldThrowExceptionIfKeyIsUnsupported() throws KeyStoreException {
        Key mockKey = mock(Key.class);
        keyVaultService.setKeyByAlias(ALIAS, mockKey);
    }

    /**
     * @verifies call delegate
     * @see KeyVaultService#getSecretByAlias(String)
     */
    @Test
    public void getSecretByAlias_shouldCallDelegate() {
        KeyVaultSecret mockBundle = mock(KeyVaultSecret.class);
        given(secretClient.getSecret(ALIAS)).willReturn(mockBundle);
        KeyVaultSecret resultBundle = keyVaultService.getSecretByAlias(ALIAS);

        verify(secretClient).getSecret(ALIAS);
        assertEquals(resultBundle, mockBundle);
    }

    /**
     * @verifies call delegate
     * @see KeyVaultService#deleteSecretByAlias(String)
     */
    @Test
    public void deleteSecretByAlias_shouldCallDelegate() {
        DeletedSecret secretBundle = mock(DeletedSecret.class);
        PollResponse<DeletedSecret> pollResponse = mock(PollResponse.class);
        SyncPoller<DeletedSecret, Void> mockPoller = mock(SyncPoller.class);
        given(pollResponse.getValue()).willReturn(secretBundle);
        given(mockPoller.waitForCompletion()).willReturn(pollResponse);
        given(secretClient.beginDeleteSecret(ALIAS)).willReturn(mockPoller);
        DeletedSecret resultBundle = this.keyVaultService.deleteSecretByAlias(ALIAS);
        verify(secretClient).beginDeleteSecret(ALIAS);
        assertEquals(resultBundle, secretBundle);
    }

    /**
     * @verifies return null if certificate is missing
     * @see KeyVaultService#getCertificateByAlias(String)
     */
    @Test
    public void getCertificateByAlias_shouldReturnNullIfCertificateIsMissing() throws Exception {
        given(certificateClient.getCertificate(ALIAS)).willReturn(null);
        KeyVaultCertificateWithPolicy certificateBundle = keyVaultService.getCertificateByAlias(ALIAS);
        verify(certificateClient).getCertificate(ALIAS);
        assertNull(certificateBundle);
    }

    /**
     * @verifies throw exception if setting secret fails
     * @see KeyVaultService#setKeyByAlias(String, Key)
     */
    @Test(expected = KeyStoreException.class)
    public void setKeyByAlias_shouldThrowExceptionIfSettingSecretFails() throws Exception {
        SecretKey mockKey = new KeyStore
            .SecretKeyEntry(new SecretKeySpec("SEKRET_KEY".getBytes(), "RAW")).getSecretKey();

        given(secretClient.setSecret(any(KeyVaultSecret.class))).willReturn(null);

        keyVaultService.setKeyByAlias(ALIAS, mockKey);
    }

    /**
     * @verifies throw exception if getting key to check fails
     * @see KeyVaultService#setKeyByAlias(String, Key)
     */
    @Test(expected = KeyStoreException.class)
    public void setKeyByAlias_shouldThrowExceptionIfGettingKeyToCheckFails() throws Exception {
        SecretKey mockKey = new KeyStore
            .SecretKeyEntry(new SecretKeySpec("SEKRET_KEY".getBytes(), "RAW")).getSecretKey();
        KeyVaultSecret bundle = mock(KeyVaultSecret.class);

        given(secretClient.setSecret(any(KeyVaultSecret.class))).willReturn(bundle);

        given(secretClient.getSecret(ALIAS)).willReturn(null);

        keyVaultService.setKeyByAlias(ALIAS, mockKey);
    }

    /**
     * @verifies produce an instance
     * @see KeyVaultService#getInstance()
     */
    @Test
    public void getInstance_shouldProduceAnInstance() {
        assertNotNull(KeyVaultService.getInstance());
    }
}
