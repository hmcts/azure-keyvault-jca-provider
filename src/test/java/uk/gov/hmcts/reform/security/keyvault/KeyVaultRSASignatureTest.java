package uk.gov.hmcts.reform.security.keyvault;

import com.azure.security.keyvault.keys.cryptography.models.SignResult;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;

import java.security.InvalidKeyException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.BDDMockito.any;
import static org.mockito.BDDMockito.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

abstract class KeyVaultRSASignatureTest {

    @Mock
    private KeyVaultService vaultService;

    @Before
    public void setUp() {
        System.setProperty(SystemPropertyKeyVaultConfigBuilder.VAULT_BASE_URL, "https://www.BASE_URL.com");
        System.setProperty(SystemPropertyKeyVaultConfigBuilder.VAULT_CLIENT_ID, "CLIENT_ID");
        System.setProperty(SystemPropertyKeyVaultConfigBuilder.VAULT_CLIENT_KEY, "CLIENT_KEY");
    }

    /**
     * Each subclass should construct the signature using the default no-args constructor
     */
    protected abstract KeyVaultRSASignature loadSignatureWithDefaultConstructor();

    protected abstract KeyVaultRSASignature getMockInjectedSignature();

    @Test
    public void defaultNoArgsConstructorShouldCreateSignature() {
        KeyVaultRSASignature signature = loadSignatureWithDefaultConstructor();
        assertNotNull(signature);
    }

    /**
     * @verifies throw exception if param is not valid
     * @see KeyVaultRSASignature#engineInitSign(java.security.PrivateKey)
     */
    @Test(expected = InvalidKeyException.class)
    public void engineInitSign_shouldThrowExceptionIfParamIsNotValid() throws Exception {
        KeyVaultRSASignature rsa = getMockInjectedSignature();
        rsa.engineInitSign(null);
    }

    /**
     * @verifies throw exception if offset is not zero
     * @see KeyVaultRSASignature#engineUpdate(byte[], int, int)
     */
    @Test(expected = UnsupportedOperationException.class)
    public void engineUpdate_shouldThrowExceptionIfOffsetIsNotZero() {
        KeyVaultRSASignature rsa = getMockInjectedSignature();
        rsa.engineUpdate(new byte[5], 1, 5);
    }

    /**
     * @verifies throw exception
     * @see KeyVaultRSASignature#engineInitVerify(java.security.PublicKey)
     */
    @Test(expected = UnsupportedOperationException.class)
    public void engineInitVerify_shouldThrowException() {
        getMockInjectedSignature().engineInitVerify(null);
    }

    /**
     * @verifies throw exception
     * @see KeyVaultRSASignature#engineUpdate(byte)
     */
    @Test(expected = UnsupportedOperationException.class)
    public void engineUpdate_shouldThrowException() {
        getMockInjectedSignature().engineUpdate((byte) 0);
    }

    /**
     * @verifies throw exception
     * @see KeyVaultRSASignature#engineVerify(byte[])
     */
    @Test(expected = UnsupportedOperationException.class)
    public void engineVerify_shouldThrowException() {
        getMockInjectedSignature().engineVerify(null);
    }

    /**
     * @verifies throw exception
     * @see KeyVaultRSASignature#engineSetParameter(String, Object)
     */
    @Test(expected = UnsupportedOperationException.class)
    public void engineSetParameter_shouldThrowException() {
        getMockInjectedSignature().engineSetParameter(null, null);
    }

    /**
     * @verifies throw exception
     * @see KeyVaultRSASignature#engineGetParameter(String)
     */
    @Test(expected = UnsupportedOperationException.class)
    public void engineGetParameter_shouldThrowException() {
        getMockInjectedSignature().engineGetParameter(null);
    }

    /**
     * @verifies set identifier if param is valid
     * @see KeyVaultRSASignature#engineInitSign(java.security.PrivateKey)
     */
    @Test
    public void engineInitSign_shouldSetIdentifierIfParamIsValid() throws Exception {
        KeyVaultRSAPrivateKey keyMock = mock(KeyVaultRSAPrivateKey.class);

        getMockInjectedSignature().engineInitSign(keyMock);

        verify(keyMock).getIdentifier();
    }

    /**
     * @verifies sign data
     * @see KeyVaultRSASignature#engineSign()
     */
    @Test
    public void engineSign_shouldSignData() throws Exception {

        KeyVaultRSAPrivateKey keyMock = mock(KeyVaultRSAPrivateKey.class);
        SignResult resultMock = mock(SignResult.class);

        given(keyMock.getIdentifier()).willReturn("id");
        given(vaultService.sign(eq("id"), eq(SignatureAlgorithm.RS256), any())).willReturn(resultMock);
        given(resultMock.getSignature()).willReturn(new byte[0]);

        byte[] rawData = "message".getBytes();
        KeyVaultRSASignature keyVaultRSASignature = getMockInjectedSignature();
        keyVaultRSASignature.engineInitSign(keyMock);
        keyVaultRSASignature.engineUpdate(rawData, 0, rawData.length);
        byte[] signedData = keyVaultRSASignature.engineSign();

        verify(keyMock).getIdentifier();
        verify(vaultService).sign(eq("id"), eq(SignatureAlgorithm.RS256), any());

        Assert.assertArrayEquals(new byte[0], signedData);
    }

    @Test
    public void clearVersionFromKey_shouldClearTheVersionFromURLs() throws Exception {
        String mockKey = "https://mockvault.vault.azure.net/keys/mockkey/mockkeyversion";
        KeyVaultRSASignature keyVaultRSASignature = getMockInjectedSignature();
        String clearedKey = keyVaultRSASignature.clearVersionFromKey(mockKey);
        assertEquals("https://mockvault.vault.azure.net/keys/mockkey/", clearedKey);
    }
}
