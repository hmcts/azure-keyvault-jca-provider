package uk.gov.hmcts.reform.security.keyvault;

import com.microsoft.azure.keyvault.models.CertificateBundle;
import com.microsoft.azure.keyvault.models.KeyBundle;
import com.microsoft.azure.keyvault.models.SecretBundle;
import com.microsoft.azure.keyvault.webkey.JsonWebKey;
import com.microsoft.azure.keyvault.webkey.JsonWebKeyType;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import javax.crypto.SecretKey;

import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@RunWith(MockitoJUnitRunner.class)
public class KeyVaultKeyStoreTest {

    private static final String ALIAS = "alias";

    private static final String DUMMY_KEY_BASE_64 = "vOX5qWDltjg1GiIrNtgo4g==";

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

    @Mock
    private KeyStoreSpi localKeyStore;

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
        KeyBundle keyBundle = mock(KeyBundle.class);
        JsonWebKey key = mock(JsonWebKey.class);
        given(vaultService.getKeyByAlias(ALIAS)).willReturn(keyBundle);
        given(keyBundle.key()).willReturn(key);
        given(key.kty()).willReturn(JsonWebKeyType.OCT);
        char[] password = "password".toCharArray();
        keyStore.engineGetKey(ALIAS, password);
    }

    /**
     * @verifies return ec key for ec key type
     * @see KeyVaultKeyStore#engineGetKey(String, char[])
     */
    @Test
    public void engineGetKey_shouldReturnEcKeyForEcKeyType() {
        KeyBundle keyBundle = mock(KeyBundle.class);
        JsonWebKey key = mock(JsonWebKey.class);
        given(keyBundle.key()).willReturn(key);
        given(key.kty()).willReturn(JsonWebKeyType.EC);
        given(key.toEC())
            .willReturn(new KeyPair(mock(PublicKey.class), mock(PrivateKey.class)));
        given(vaultService.getKeyByAlias(eq(ALIAS))).willReturn(keyBundle);
        char[] password = "password".toCharArray();
        keyStore.engineGetKey(ALIAS, password);

        verify(vaultService).getKeyByAlias(eq(ALIAS));
    }

    /**
     * @verifies fetch Secret Key if Key by Alias fails
     * @see KeyVaultKeyStore#engineGetKey(String, char[])
     */
    @Test
    public void engineGetKey_shouldFetchSecretKeyIfKeyByAliasFails() {
        char[] password = "password".toCharArray();
        given(vaultService.getKeyByAlias(eq(ALIAS))).willReturn(null);
        SecretBundle keyBundle = new SecretBundle().withValue("value");
        given(vaultService.getSecretByAlias(eq(ALIAS))).willReturn(keyBundle);

        keyStore.engineGetKey(ALIAS, password);

        verify(vaultService).getSecretByAlias(eq(ALIAS));
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
        CertificateBundle certBundle = mock(CertificateBundle.class);
        given(certBundle.cer()).willReturn(Base64.getDecoder().decode(DUMMY_CERT_BASE_64));
        given(vaultService.getCertificateByAlias(eq("test"))).willReturn(certBundle);

        Certificate certificate = keyStore.engineGetCertificate(ALIAS);

        verify(vaultService).getCertificateByAlias(eq(ALIAS));

        assertNotNull(certificate);
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
     * @verifies return a date
     * @see KeyVaultKeyStore#engineGetCreationDate(String)
     */
    @Test
    public void engineGetCreationDate_shouldReturnADate() {
        given(localKeyStore.engineGetCreationDate(any())).willReturn(new Date());
        assertNotNull(keyStore.engineGetCreationDate(ALIAS));
    }

    /**
     * @verifies return an enumeration
     * @see KeyVaultKeyStore#engineAliases()
     */
    @Test
    public void engineAliases_shouldReturnAnEnumeration() {
        Enumeration<String> enumeration = keyStore.engineAliases();
        assertFalse(enumeration.hasMoreElements());
    }

    /**
     * @verifies return true when vault contains a certificate with the required alias
     * @see KeyVaultKeyStore#engineContainsAlias(String)
     */
    @Test
    public void engineContainsAlias_shouldReturnTrueWhenVaultContainsACertificateWithTheRequiredAlias()
        throws Exception {
        CertificateBundle certBundle = mock(CertificateBundle.class);
        given(vaultService.getCertificateByAlias(eq(ALIAS))).willReturn(certBundle);

        assertTrue(keyStore.engineContainsAlias(ALIAS));
    }

    /**
     * @verifies return true when vault contains a key with the required alias
     * @see KeyVaultKeyStore#engineContainsAlias(String)
     */
    @Test
    public void engineContainsAlias_shouldReturnTrueWhenVaultContainsAKeyWithTheRequiredAlias() {
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
     * @see KeyVaultKeyStore#engineGetCertificateAlias(java.security.cert.Certificate)
     */
    @Test(expected = UnsupportedOperationException.class)
    public void engineGetCertificateAlias_shouldThrowException() {
        keyStore.engineGetCertificateAlias(null);
    }

    /**
     * @verifies return true if alias is within list
     * @see KeyVaultKeyStore#engineIsKeyEntry(String)
     */
    @Test
    public void engineIsKeyEntry_shouldReturnTrueIfAliasIsWithinList() {
        given(vaultService.engineKeyAliases()).willReturn(Collections.singletonList(ALIAS));
        assertTrue(keyStore.engineIsKeyEntry(ALIAS));
    }

    /**
     * @verifies return false if alias is not within list
     * @see KeyVaultKeyStore#engineIsKeyEntry(String)
     */
    @Test
    public void engineIsKeyEntry_shouldReturnFalseIfAliasIsNotWithinList() {
        given(vaultService.engineKeyAliases()).willReturn(Collections.EMPTY_LIST);
        assertFalse(keyStore.engineIsKeyEntry(ALIAS));
    }

    /**
     * @verifies return false if entry isn't in keyvault
     * @see KeyVaultKeyStore#engineEntryInstanceOf(String, Class)
     */
    @Test
    public void engineEntryInstanceOf_shouldReturnFalseIfEntryIsntInKeyvault() throws Exception {
        given(vaultService.getKeyByAlias(ALIAS)).willReturn(null);
        given(vaultService.getCertificateByAlias(ALIAS)).willReturn(null);
        assertFalse(keyStore.engineEntryInstanceOf(ALIAS, KeyStore.TrustedCertificateEntry.class));
        assertFalse(keyStore.engineEntryInstanceOf(ALIAS, KeyStore.PrivateKeyEntry.class));
        assertFalse(keyStore.engineEntryInstanceOf(ALIAS, KeyStore.SecretKeyEntry.class));
    }

    /**
     * @verifies return entry is certificate or entry is secret
     * @see KeyVaultKeyStore#engineEntryInstanceOf(String, Class)
     */
    @Test
    public void engineEntryInstanceOf_shouldReturnEntryIsCertificateOrEntryIsSecret() {
        KeyBundle keyBundle = mock(KeyBundle.class);
        CertificateBundle certificateBundle = mock(CertificateBundle.class);
        given(vaultService.getKeyByAlias(ALIAS)).willReturn(keyBundle);
        given(vaultService.getCertificateByAlias(ALIAS)).willReturn(certificateBundle);
        assertTrue(keyStore.engineEntryInstanceOf(ALIAS, KeyStore.TrustedCertificateEntry.class));
        assertTrue(keyStore.engineEntryInstanceOf(ALIAS, KeyStore.PrivateKeyEntry.class));
        assertFalse(keyStore.engineEntryInstanceOf(ALIAS, KeyStore.SecretKeyEntry.class));
    }

    /**
     * @verifies Call Delegate
     * @see KeyVaultKeyStore#engineDeleteEntry(String)
     */
    @Test
    public void engineDeleteEntry_shouldCallDelegate() throws KeyStoreException {
        SecretBundle secretBundle = mock(SecretBundle.class);
        given(vaultService.deleteSecretByAlias(ALIAS)).willReturn(secretBundle);
        keyStore.engineDeleteEntry(ALIAS);
        verify(vaultService).deleteSecretByAlias(ALIAS);
    }

    /**
     * @verifies return true if certificate is in keyvault
     * @see KeyVaultKeyStore#engineIsCertificateEntry(String)
     */
    @Test
    public void engineIsCertificateEntry_shouldReturnTrueIfCertificateIsInKeyvault() {
        CertificateBundle certificateBundle = mock(CertificateBundle.class);
        given(vaultService.getCertificateByAlias(ALIAS)).willReturn(certificateBundle);
        assertTrue(keyStore.engineIsCertificateEntry(ALIAS));
    }

    /**
     * @verifies call Delegate
     * @see KeyVaultKeyStore#engineSetKeyEntry(String, Key, char[], Certificate[])
     */
    @Test
    public void engineSetKeyEntry_shouldCallDelegate() throws KeyStoreException {
        SecretKey key = mock(SecretKey.class);
        SecretBundle secretBundle = mock(SecretBundle.class);
        given(vaultService.setKeyByAlias(ALIAS, key)).willReturn(secretBundle);
        keyStore.engineSetKeyEntry(ALIAS, key, null, null);
        verify(vaultService).setKeyByAlias(ALIAS, key);
    }

    /**
     * @verifies return false if certificate isn't in keyvault
     * @see KeyVaultKeyStore#engineIsCertificateEntry(String)
     */
    @Test
    public void engineIsCertificateEntry_shouldReturnFalseIfCertificateIsntInKeyvault() {
        given(vaultService.getCertificateByAlias(ALIAS)).willReturn(null);
        assertFalse(keyStore.engineIsCertificateEntry(ALIAS));
    }

    /**
     * @verifies fetch sms-transport-key if called for sms.transport.key
     * @see KeyVaultKeyStore#engineGetKey(String, char[])
     */
    @Test
    public void engineGetKey_shouldFetchSmstransportkeyIfCalledForSmstransportkey() {
        char[] password = "password".toCharArray();
        SecretBundle keyBundle = new SecretBundle().withValue(DUMMY_KEY_BASE_64);
        given(vaultService.getSecretByAlias(eq("sms-transport-key"))).willReturn(keyBundle);

        SecretKey key = (SecretKey) keyStore.engineGetKey("sms.transport.key", password);

        verify(vaultService).getSecretByAlias(eq("sms-transport-key"));

        assertTrue(Base64.getEncoder()
                       .encodeToString(key.getEncoded())
                       .equalsIgnoreCase(DUMMY_KEY_BASE_64));
    }

    /**
     * @verifies return null if no keys are found
     * @see KeyVaultKeyStore#engineGetKey(String, char[])
     */
    @Test
    public void engineGetKey_shouldReturnNullIfNoKeysAreFound() {
        char[] password = "password".toCharArray();
        given(vaultService.getKeyByAlias(eq(ALIAS))).willReturn(null);
        given(vaultService.getSecretByAlias(eq(ALIAS))).willReturn(null);

        Key key = keyStore.engineGetKey(ALIAS, password);

        verify(vaultService).getKeyByAlias(eq(ALIAS));
        verify(vaultService).getSecretByAlias(eq(ALIAS));

        assertNull(key);
    }

    /**
     * @verifies return null if no sms-transport-key exists when called with sms.transport.key
     * @see KeyVaultKeyStore#engineGetKey(String, char[])
     */
    @Test
    public void engineGetKey_shouldReturnNullIfNoSmstransportkeyExistsWhenCalledWithSmstransportkey() {
        char[] password = "password".toCharArray();
        given(vaultService.getSecretByAlias(eq("sms-transport-key"))).willReturn(null);

        SecretKey key = (SecretKey) keyStore.engineGetKey("sms.transport.key", password);

        verify(vaultService).getSecretByAlias(eq("sms-transport-key"));

        assertNull(key);
    }

    /**
     * @verifies return false when exception is thrown
     * @see KeyVaultKeyStore#engineContainsAlias(String)
     */
    @Test
    public void engineContainsAlias_shouldReturnFalseWhenExceptionIsThrown() {
        given(vaultService.getKeyByAlias(eq(ALIAS))).willThrow(new NullPointerException());
        assertFalse(keyStore.engineContainsAlias(ALIAS));
    }

    /**
     * @verifies return false if class is not supported
     * @see KeyVaultKeyStore#engineEntryInstanceOf(String, Class)
     */
    @Test
    public void engineEntryInstanceOf_shouldReturnFalseIfClassIsNotSupported() {
        assertFalse(keyStore.engineEntryInstanceOf(ALIAS, KeyStore.Entry.class));
    }

    /**
     * @verifies try save SecretKeys in local store to KeyVault
     * @see KeyVaultKeyStore#engineGetKey(String, char[])
     */
    @Test
    public void engineGetKey_shouldTrySaveSecretKeysInLocalStoreToKeyVault() throws Exception {
        assertNull(keyStore.engineGetKey("A_KEY", "A_PASSWORD".toCharArray()));
    }

    /**
     * @verifies try engine store the stream
     * @see KeyVaultKeyStore#engineStore(java.io.OutputStream, char[])
     */
    @Test
    public void engineStore_shouldTryEngineStoreTheStream() throws Exception {
        keyStore.engineStore(mock(OutputStream.class), new char[0]);
        verify(localKeyStore).engineStore(any(), any());
    }

    /**
     * @verifies return the engine size
     * @see KeyVaultKeyStore#engineSize()
     */
    @Test
    public void engineSize_shouldReturnTheEngineSize() throws Exception {
        given(vaultService.engineKeyAliases()).willReturn(Arrays.asList("1", "2", "3"));
        given(vaultService.engineCertificateAliases()).willReturn(Arrays.asList("1", "2"));
        assertEquals(keyStore.engineSize(), 5);
    }

    /**
     * @verifies engine load
     * @see KeyVaultKeyStore#engineLoad(InputStream, char[])
     */
    @Test
    public void engineLoad_shouldEngineLoad() throws Exception {
        keyStore.engineLoad(mock(InputStream.class), new char[0]);
        assertNull(keyStore.engineGetKey("A_KEY", "A_PASSWORD".toCharArray()));
    }

    /**
     * @verifies throw exception if certificate exception is thrown
     * @see KeyVaultKeyStore#engineGetCertificate(String)
     */
    @Test(expected = ProviderException.class)
    public void engineGetCertificate_shouldThrowExceptionIfCertificateExceptionIsThrown() throws Exception {
        given(vaultService.getCertificateByAlias(eq(ALIAS))).willReturn(null);
        CertificateBundle certBundle = mock(CertificateBundle.class);
        given(certBundle.cer()).willReturn("not a certificate".getBytes());
        given(vaultService.getCertificateByAlias(eq("test"))).willReturn(certBundle);
        keyStore.engineGetCertificate(ALIAS);
    }
}
