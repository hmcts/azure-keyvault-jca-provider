package uk.gov.hmcts.reform.security.keyvault;

import com.microsoft.azure.PagedList;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.models.CertificateBundle;
import com.microsoft.azure.keyvault.models.KeyBundle;
import com.microsoft.azure.keyvault.models.KeyItem;
import com.microsoft.azure.keyvault.models.SecretBundle;
import com.microsoft.azure.keyvault.models.SecretItem;
import com.microsoft.azure.keyvault.requests.SetSecretRequest;
import com.microsoft.azure.keyvault.webkey.JsonWebKeySignatureAlgorithm;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class KeyVaultServiceTest {

    private static final String ALIAS = "ALIAS";

    private static final String BASE_URL = "BASE_URL";

    private static final String KEY_IDENTIFIER = "KEY_ID";

    @Mock
    private KeyVaultClient vaultClient;

    private KeyVaultService keyVaultService;

    @Before
    public void setUp() {
        System.setProperty(SystemPropertyKeyVaultConfigBuilder.VAULT_BASE_URL, BASE_URL);
        keyVaultService = new KeyVaultService(new SystemPropertyKeyVaultConfigBuilder().build(), vaultClient);
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

    /**
     * @verifies call delegate if key is SecretKey
     * @see KeyVaultService#setKeyByAlias(String, java.security.Key)
     */
    @Test
    public void setKeyByAlias_shouldCallDelegateIfKeyIsSecretKey() {
        SecretKey mockKey = new KeyStore
            .SecretKeyEntry(new SecretKeySpec("SEKRET_KEY".getBytes(), "RAW")).getSecretKey();
        SecretBundle bundle = mock(SecretBundle.class);
        given(vaultClient.setSecret(any(SetSecretRequest.class))).willReturn(bundle);

        SecretBundle resultBundle = keyVaultService.setKeyByAlias(ALIAS, mockKey);

        verify(vaultClient).setSecret(any(SetSecretRequest.class));
        assertEquals(bundle, resultBundle);
    }

    /**
     * @verifies throw exception if key is unsupported
     * @see KeyVaultService#setKeyByAlias(String, java.security.Key)
     */
    @Test(expected = UnsupportedOperationException.class)
    public void setKeyByAlias_shouldThrowExceptionIfKeyIsUnsupported() {
        Key mockKey = mock(Key.class);
        keyVaultService.setKeyByAlias(ALIAS, mockKey);
    }

    /**
     * @verifies call delegate
     * @see KeyVaultService#getSecretByAlias(String)
     */
    @Test
    public void getSecretByAlias_shouldCallDelegate() {
        SecretBundle mockBundle = mock(SecretBundle.class);
        given(vaultClient.getSecret(BASE_URL, ALIAS)).willReturn(mockBundle);
        SecretBundle resultBundle = keyVaultService.getSecretByAlias(ALIAS);

        verify(vaultClient).getSecret(BASE_URL, ALIAS);
        assertEquals(resultBundle, mockBundle);
    }

    /**
     * @verifies call delegate and return parsed list
     * @see KeyVaultService#engineAliases()
     */
    @Test
    public void engineAliases_shouldCallDelegateAndReturnParsedList() {
        List<SecretItem> secretItems = Arrays.asList(new SecretItem().withId("https://myvault.vault.azure.net/secrets/help/abc123xyz789"),
            new SecretItem().withId("https://myvault.vault.azure.net/secrets/get-me/abc123xyz789"));
        List<KeyItem> keyItems = Arrays.asList(new KeyItem().withKid("https://myvault.vault.azure.net/keys/the-hell/abc123xyz789"),
            new KeyItem().withKid("https://myvault.vault.azure.net/keys/outta-here/abc123xyz789"));

        PagedList<SecretItem> mockSecretPagedList = mock(PagedList.class);
        PagedList<KeyItem> mockKeyPagedList = mock(PagedList.class);

        doAnswer(invocation -> {
            Consumer<SecretItem> arg0 = invocation.getArgument(0);
            secretItems.forEach(arg0::accept);
            return null;
        }).when(mockSecretPagedList).forEach(any(Consumer.class));
        doAnswer(invocation -> {
            Consumer<KeyItem> arg0 = invocation.getArgument(0);
            keyItems.forEach(arg0::accept);
            return null;
        }).when(mockKeyPagedList).forEach(any(Consumer.class));

        given(this.vaultClient.listSecrets(BASE_URL)).willReturn(mockSecretPagedList);
        given(this.vaultClient.listKeys(BASE_URL)).willReturn(mockKeyPagedList);

        List<String> listOfAliases = this.keyVaultService.engineAliases();
        assertEquals(listOfAliases, Arrays.asList("help", "get-me", "the-hell", "outta-here"));
    }

    /**
     * @verifies call delegate
     * @see KeyVaultService#deleteSecretByAlias(String)
     */
    @Test
    public void deleteSecretByAlias_shouldCallDelegate() {
        SecretBundle secretBundle = mock(SecretBundle.class);
        given(this.vaultClient.deleteSecret(BASE_URL, ALIAS)).willReturn(secretBundle);
        SecretBundle resultBundle = this.keyVaultService.deleteSecretByAlias(ALIAS);
        verify(vaultClient).deleteSecret(BASE_URL, ALIAS);
        assertEquals(resultBundle, secretBundle);
    }
}
