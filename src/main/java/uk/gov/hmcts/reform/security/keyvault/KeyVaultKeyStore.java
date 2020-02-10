package uk.gov.hmcts.reform.security.keyvault;

import com.microsoft.azure.keyvault.models.CertificateBundle;
import com.microsoft.azure.keyvault.models.KeyBundle;
import com.microsoft.azure.keyvault.models.SecretBundle;
import com.microsoft.azure.keyvault.webkey.JsonWebKey;
import com.microsoft.azure.keyvault.webkey.JsonWebKeyType;
import com.sun.crypto.provider.JceKeyStore;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import javax.crypto.spec.SecretKeySpec;

public final class KeyVaultKeyStore extends KeyStoreSpi {

    private static final String SMS_TRANSPORT_KEY_DASHES = "sms-transport-key";

    private static final String SMS_TRANSPORT_KEY_DOTS = "sms.transport.key";

    private KeyVaultService vaultService;

    private KeyStoreSpi localKeyStore = new JceKeyStore();

    /**
     * @should return rsa private key for rsa alias
     * @should throw provider exception for unsupported key type
     * @should fetch Secret Key if Key by Alias fails
     * @should fetch sms-transport-key if called for sms.transport.key
     * @should return null if no sms-transport-key exists when called with sms.transport.key
     * @should return null if no keys are found
     * @should try save SecretKeys in local store to KeyVault
     */
    @Override
    public Key engineGetKey(final String alias, final char[] password) {
        if (localKeyStore.engineIsKeyEntry(alias)) {
            try {
                Key engineKey = localKeyStore.engineGetKey(alias, password);
                if (engineKey instanceof SecretKeySpec) {
                    System.out.println("Key \"" + alias + "\" is secret key in local keystore,"
                                           + " saving to KeyVault");
                    vaultService.setKeyByAlias(alias, engineKey);
                }
            } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
                System.out.println("Unable to save key to KeyVault : " + alias);
                e.printStackTrace();
            }
        }

        if (alias.equalsIgnoreCase(SMS_TRANSPORT_KEY_DASHES)
            || alias.equalsIgnoreCase(SMS_TRANSPORT_KEY_DOTS)) {
            return getSmsTransportKey();
        }

        KeyBundle keyBundle = vaultService.getKeyByAlias(alias);
        if (keyBundle != null) {
            // Found a key-pair for this alias
            JsonWebKey key = keyBundle.key();
            JsonWebKeyType keyType = key.kty();
            if (JsonWebKeyType.RSA.equals(keyType) || JsonWebKeyType.RSA_HSM.equals(keyType)) {
                return new KeyVaultRSAPrivateKey(keyBundle.keyIdentifier().identifier(), JsonWebKeyType.RSA.toString());
            } else {
                throw new ProviderException("JsonWebKeyType [" + keyType + "] not implemented");
            }
        } else {
            // Try looking up a secret based on this alias
            SecretBundle bundle = vaultService.getSecretByAlias(alias);
            if (bundle != null) {
                KeyStore.SecretKeyEntry entry = new KeyStore
                    .SecretKeyEntry(new SecretKeySpec(bundle.value().getBytes(), "RAW"));
                return entry.getSecretKey();
            }
        }
        return null;
    }

    private Key getSmsTransportKey() {
        final SecretBundle bundle = vaultService.getSecretByAlias(SMS_TRANSPORT_KEY_DASHES);
        if (bundle != null) {
            // decode the base64 encoded string
            byte[] decodedKey = Base64.getDecoder().decode(bundle.value());
            // use only first 128 bit
            decodedKey = Arrays.copyOf(decodedKey, 16);
            KeyStore.SecretKeyEntry entry = new KeyStore
                .SecretKeyEntry(new SecretKeySpec(decodedKey, "AES"));
            return entry.getSecretKey();
        }
        return null;
    }

    /**
     * @should throw exception
     */
    @Override
    public Certificate[] engineGetCertificateChain(final String alias) {
        throw new UnsupportedOperationException();
    }

    /**
     * @should return certificate when vault contains the certificate
     * @should return null when vault does not contain the alias
     */
    @Override
    public Certificate engineGetCertificate(final String alias) {
        System.out.println("Engine get certificate called with " + alias);
        CertificateBundle certificateBundle = vaultService.getCertificateByAlias(alias);
        if (certificateBundle == null) {
            return null;
        }

        X509Certificate certificate;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateBundle.cer()));
        } catch (CertificateException e) {
            throw new ProviderException(e);
        }

        return new KeyVaultCertificate(certificate);
    }

    /**
     * @should throw exception
     */
    @Override
    public Date engineGetCreationDate(final String alias) {
        throw new UnsupportedOperationException();
    }

    /**
     * @should call Delegate
     */
    @Override
    public void engineSetKeyEntry(final String alias, final Key key, final char[] password, final Certificate[] chain)
        throws KeyStoreException {
        vaultService.setKeyByAlias(alias, key);
    }

    /**
     * @should throw exception
     */
    @Override
    public void engineSetKeyEntry(final String alias, final byte[] key, final Certificate[] chain) {
        throw new UnsupportedOperationException();
    }

    /**
     * @should throw exception
     */
    @Override
    public void engineSetCertificateEntry(final String alias, final Certificate cert) {
        throw new UnsupportedOperationException();
    }

    /**
     * @should Call Delegate
     */
    @Override
    public void engineDeleteEntry(final String alias) {
        vaultService.deleteSecretByAlias(alias);
    }

    /**
     * Dots replaced with dashes will come back as dots in this list
     *
     * @should return an enumeration
     */
    @Override
    public Enumeration<String> engineAliases() {
        final List<String> allAliases =
            new ArrayList<>(vaultService.engineKeyAliases());
        allAliases.addAll(vaultService.engineCertificateAliases());
        return Collections.enumeration(allAliases);
    }

    /**
     * @should return false when exception is thrown
     * @should return true when vault contains a key with the required alias
     * @should return false when vault does not contain the alias
     */
    @Override
    public boolean engineContainsAlias(final String alias) {
        try {
            return vaultService.getKeyByAlias(alias) != null
                || vaultService.getSecretByAlias(alias) != null
                || vaultService.getCertificateByAlias(alias) != null;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * @should throw exception
     */
    @Override
    public int engineSize() {
        throw new UnsupportedOperationException();
    }

    /**
     * Does Key Exist in Key Store
     *
     * @should return true if alias is within list
     * @should return false if alias is not within list
     */
    @Override
    public boolean engineIsKeyEntry(final String alias) {
        final List<String> aliases = vaultService.engineKeyAliases();
        return aliases.stream().anyMatch(vaultAlias -> vaultAlias.equalsIgnoreCase(alias));
    }

    /**
     * @should return true if certificate is in keyvault
     * @should return false if certificate isn't in keyvault
     */
    @Override
    public boolean engineIsCertificateEntry(final String alias) {
        return vaultService.getCertificateByAlias(alias) != null;
    }

    /**
     * @should return entry is certificate or entry is secret
     * @should return false if entry isn't in keyvault
     * @should return false if class is not supported
     */
    @Override
    public boolean engineEntryInstanceOf(final String alias,
                                         final Class<? extends KeyStore.Entry> entryClass) {
        if (entryClass == KeyStore.TrustedCertificateEntry.class) {
            return engineIsCertificateEntry(alias);
        }
        if (entryClass == KeyStore.PrivateKeyEntry.class
            || entryClass == KeyStore.SecretKeyEntry.class) {
            return vaultService.getKeyByAlias(alias) != null
                || vaultService.getSecretByAlias(alias) != null;
        }
        return false;
    }

    /**
     * @should throw exception
     */
    @Override
    public String engineGetCertificateAlias(final Certificate cert) {
        throw new UnsupportedOperationException();
    }

    /**
     * @should try engine store the stream
     */
    @Override
    public void engineStore(final OutputStream stream, final char[] password)
        throws IOException, NoSuchAlgorithmException, CertificateException {
        localKeyStore.engineStore(stream, password);
    }

    /**
     * @should try engine load the stream
     */
    @Override
    public void engineLoad(final InputStream stream, final char[] password)
        throws CertificateException, NoSuchAlgorithmException, IOException {
        vaultService = KeyVaultService.getInstance();
        if (stream != null) {
            localKeyStore.engineLoad(stream, password);
        }
    }
}
