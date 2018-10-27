package uk.gov.hmcts.reform.security.keyvault;

import com.microsoft.azure.keyvault.models.CertificateBundle;
import com.microsoft.azure.keyvault.models.KeyBundle;
import com.microsoft.azure.keyvault.webkey.JsonWebKey;
import com.microsoft.azure.keyvault.webkey.JsonWebKeyType;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.security.Key;
import java.security.ProviderException;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Enumeration;

import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@RunWith(MockitoJUnitRunner.class)
public class KeyVaultKeyStoreTest {

    private static final String ALIAS = "alias";

    private static final String KEY_IDENTIFIER = "https://myvault.vault.azure.net/keys/my-key/abc123xyz789";

    private static final String DUMMY_CERT_BASE_64 =
        "MIIDJDCCAgygAwIBAgIQCnxzkpdMTCaQw8utyofOQTANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDEwR0ZXN0MB4XDTE4MDQxMTEzMTUzOVo"
            + "XDTE5MDQxMTEzMjUzOVowDzENMAsGA1UEAxMEdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALsneO/yxkO+EcKXq+"
            + "802ief5VTGRQcDyEYtlaavz3wfmqfsC6lF5GOLaNmoSCfJD4tc6Co55Zxj7FXOPP+MMhDU/y6ZNq7Vnv+TgDd3uztj2SO0QlxkTvauT"
            + "8bKZHxwiuQmkzWg8FgCB3EiMXIknSZBzneFg/7vyQ0Tr+0Ca1efyvhi8df9Dps9URu//g6tnr6pXdBeC9fOh3Nkb1ezlUGox8/0k2cB"
            + "28KV41rW11Q6MM7u/jWYymwdirJtrI2sY9i7ZuQBT5LaLNt2zT3VhDtsAnAVtIgrab92mylhLl6PfyofLLCCQ4YgW2yH1sjCSohdowy"
            + "e3a7LFiEoSxTv7dECAwEAAaN8MHowDgYDVR0PAQH/BAQDAgWgMAkGA1UdEwQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBw"
            + "MCMB8GA1UdIwQYMBaAFGHMFcpRp+3C7xWnr/Z5BaAtRbTqMB0GA1UdDgQWBBRhzBXKUaftwu8Vp6/2eQWgLUW06jANBgkqhkiG9w0BA"
            + "QsFAAOCAQEAqoXryfrU8lvwh81pMBkEbSvvdoT67OlPB6rwSmAeWe06tfL5xpLClZj+wfpCi98KXFV2j451k9zVoMc092wqCYiDLtv9"
            + "OHY17XQNJsoA6rzxHSi7jvwc5bKLXFw1aH31y/thM7t1zU8eBdfOxSCOD2Hk9NDzTGHENh1YG7siZfyNhzBIiMZpdunFmCJd84EwO9R"
            + "fcqt54a0eveuJ50bGkgn9SzLlg/MMAgXs4W74QqfYoLjI7O0haAygH8uwYLeqCFdk88rdagZscx1w2rmYzz2h9EY7CB/Rd5WtQeqA5M"
            + "jjDv3Am2ShleJ8qpvxUET+UXtYtCgelNjr173kA8OSXw==";
    @Mock
    private KeyVaultService vaultService;

    @InjectMocks
    private KeyVaultKeyStore keyStore;

    /**
     * @verifies return rsa private key for rsa alias
     * @see KeyVaultKeyStore#engineGetKey(String, char[])
     */
    @Test
    public void engineGetKey_shouldReturnRsaPrivateKeyForRsaAlias() {
        char[] password = "password".toCharArray();
        KeyBundle keyBundle = new KeyBundle().withKey(
            new JsonWebKey().withKty(JsonWebKeyType.RSA).withKid(KEY_IDENTIFIER));
        given(vaultService.getKeyByAlias(eq(ALIAS))).willReturn(keyBundle);

        Key key = keyStore.engineGetKey(ALIAS, password);

        verify(vaultService).getKeyByAlias(eq(ALIAS));

        assertThat(key, instanceOf(KeyVaultRSAPrivateKey.class));
    }

    /**
     * @verifies throw provider exception for unsupported key type
     * @see KeyVaultKeyStore#engineGetKey(String, char[])
     */
    @Test(expected = ProviderException.class)
    public void engineGetKey_shouldThrowProviderExceptionForUnsupportedKeyType() {
        char[] password = "password".toCharArray();
        KeyBundle keyBundle = new KeyBundle().withKey(
            new JsonWebKey().withKty(JsonWebKeyType.EC).withKid(KEY_IDENTIFIER));
        given(vaultService.getKeyByAlias(eq(ALIAS))).willReturn(keyBundle);

        keyStore.engineGetKey(ALIAS, password);

        verify(vaultService).getKeyByAlias(eq(ALIAS));
    }

    /**
     * @verifies throw provider exception for secret key
     * @see KeyVaultKeyStore#engineGetKey(String, char[])
     */
    @Test(expected = ProviderException.class)
    public void engineGetKey_shouldThrowProviderExceptionForSecretKey() {
        char[] password = "password".toCharArray();
        given(vaultService.getKeyByAlias(eq(ALIAS))).willReturn(null);

        keyStore.engineGetKey(ALIAS, password);

        verify(vaultService).getKeyByAlias(eq(ALIAS));
    }


    /**
     * @verifies return certificate when vault contains the certificate
     * @see KeyVaultKeyStore#engineGetCertificate(String)
     */
    @Test
    public void engineGetCertificate_shouldReturnCertificateWhenVaultContainsTheCertificate() {
        CertificateBundle certBundle = mock(CertificateBundle.class);
        given(certBundle.cer()).willReturn(Base64.getDecoder().decode(DUMMY_CERT_BASE_64));
        given(vaultService.getCertificateByAlias(eq(ALIAS))).willReturn(certBundle);

        Certificate certificate = keyStore.engineGetCertificate(ALIAS);

        verify(vaultService).getCertificateByAlias(eq(ALIAS));

        assertNotNull(certificate);
        assertNotNull(certificate.getPublicKey());
    }

    /**
     * @verifies return null when vault does not contain the alias
     * @see KeyVaultKeyStore#engineGetCertificate(String)
     */
    @Test
    public void engineGetCertificate_shouldReturnNullWhenVaultDoesNotContainTheAlias() {
        given(vaultService.getCertificateByAlias(eq(ALIAS))).willReturn(null);

        Certificate certificate = keyStore.engineGetCertificate(ALIAS);

        verify(vaultService).getCertificateByAlias(eq(ALIAS));

        assertNull(certificate);
    }

    /**
     * @verifies throw exception
     * @see KeyVaultKeyStore#engineGetCertificateChain(String)
     */
    @Test(expected = UnsupportedOperationException.class)
    public void engineGetCertificateChain_shouldThrowException() {
        keyStore.engineGetCertificateChain(ALIAS);
    }

    /**
     * @verifies throw exception
     * @see KeyVaultKeyStore#engineGetCreationDate(String)
     */
    @Test(expected = UnsupportedOperationException.class)
    public void engineGetCreationDate_shouldThrowException() {
        keyStore.engineGetCreationDate(ALIAS);
    }

    /**
     * @verifies throw exception
     * @see KeyVaultKeyStore#engineSetKeyEntry(String, Key, char[], java.security.cert.Certificate[])
     */
    @Test(expected = UnsupportedOperationException.class)
    public void engineSetKeyEntry_shouldThrowException() {
        keyStore.engineSetKeyEntry(ALIAS, null, null, null);
    }

    /**
     * @verifies throw exception
     * @see KeyVaultKeyStore#engineSetKeyEntry(String, byte[], java.security.cert.Certificate[])
     */
    @Test(expected = UnsupportedOperationException.class)
    public void engineSetKeyEntry_shouldThrowException2() {
        keyStore.engineSetKeyEntry(ALIAS, null, null);
    }

    /**
     * @verifies throw exception
     * @see KeyVaultKeyStore#engineSetCertificateEntry(String, java.security.cert.Certificate)
     */
    @Test(expected = UnsupportedOperationException.class)
    public void engineSetCertificateEntry_shouldThrowException() {
        keyStore.engineSetCertificateEntry(ALIAS, null);
    }

    /**
     * @verifies throw exception
     * @see KeyVaultKeyStore#engineDeleteEntry(String)
     */
    @Test(expected = UnsupportedOperationException.class)
    public void engineDeleteEntry_shouldThrowException() {
        keyStore.engineDeleteEntry(ALIAS);
    }

    /**
     * @verifies return an empty enumeration
     * @see KeyVaultKeyStore#engineAliases()
     */
    @Test
    public void engineAliases_shouldReturnAnEmptyEnumeration() {
        Enumeration<String> enumeration = keyStore.engineAliases();
        assertFalse(enumeration.hasMoreElements());
    }

    /**
     * @verifies return true when vault contains a certificate with the required alias
     * @see KeyVaultKeyStore#engineContainsAlias(String)
     */
    @Test
    public void engineContainsAlias_shouldReturnTrueWhenVaultContainsACertificateWithTheRequiredAlias() throws Exception {
        CertificateBundle certBundle = mock(CertificateBundle.class);
        given(vaultService.getCertificateByAlias(eq(ALIAS))).willReturn(certBundle);

        assertTrue(keyStore.engineContainsAlias(ALIAS));
    }

    /**
     * @verifies return true when vault contains a key with the required alias
     * @see KeyVaultKeyStore#engineContainsAlias(String)
     */
    @Test
    public void engineContainsAlias_shouldReturnTrueWhenVaultContainsAKeyWithTheRequiredAlias() throws Exception {
        KeyBundle keyBundle = mock(KeyBundle.class);
        given(vaultService.getKeyByAlias(eq(ALIAS))).willReturn(keyBundle);

        assertTrue(keyStore.engineContainsAlias(ALIAS));
    }

    /**
     * @verifies return false when vault does not contain the alias
     * @see KeyVaultKeyStore#engineContainsAlias(String)
     */
    @Test
    public void engineContainsAlias_shouldReturnFalseWhenVaultDoesNotContainTheAlias() throws Exception {
        given(vaultService.getCertificateByAlias(eq(ALIAS))).willReturn(null);
        given(vaultService.getKeyByAlias(eq(ALIAS))).willReturn(null);

        assertFalse(keyStore.engineContainsAlias(ALIAS));
    }

    /**
     * @verifies throw exception
     * @see KeyVaultKeyStore#engineSize()
     */
    @Test(expected = UnsupportedOperationException.class)
    public void engineSize_shouldThrowException() {
        keyStore.engineSize();
    }

    /**
     * @verifies throw exception
     * @see KeyVaultKeyStore#engineIsKeyEntry(String)
     */
    @Test(expected = UnsupportedOperationException.class)
    public void engineIsKeyEntry_shouldThrowException() {
        keyStore.engineIsKeyEntry(ALIAS);
    }

    /**
     * @verifies throw exception
     * @see KeyVaultKeyStore#engineIsCertificateEntry(String)
     */
    @Test(expected = UnsupportedOperationException.class)
    public void engineIsCertificateEntry_shouldThrowException() {
        keyStore.engineIsCertificateEntry(ALIAS);
    }

    /**
     * @verifies throw exception
     * @see KeyVaultKeyStore#engineGetCertificateAlias(java.security.cert.Certificate)
     */
    @Test(expected = UnsupportedOperationException.class)
    public void engineGetCertificateAlias_shouldThrowException() {
        keyStore.engineGetCertificateAlias(null);
    }

    /**
     * @verifies throw exception
     * @see KeyVaultKeyStore#engineStore(java.io.OutputStream, char[])
     */
    @Test(expected = UnsupportedOperationException.class)
    public void engineStore_shouldThrowException() {
        keyStore.engineStore(null, null);
    }
}
