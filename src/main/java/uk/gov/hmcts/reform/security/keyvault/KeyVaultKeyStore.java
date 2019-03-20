package uk.gov.hmcts.reform.security.keyvault;

import com.microsoft.azure.keyvault.models.CertificateBundle;
import com.microsoft.azure.keyvault.models.KeyBundle;
import com.microsoft.azure.keyvault.models.SecretBundle;
import com.microsoft.azure.keyvault.webkey.JsonWebKey;
import com.microsoft.azure.keyvault.webkey.JsonWebKeyType;

import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.ProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

public final class KeyVaultKeyStore extends KeyStoreSpi {

    private KeyVaultService vaultService;

    /**
     * @should return rsa private key for rsa alias
     * @should throw provider exception for unsupported key type
     * @should fetch Secret Key if Key by Alias fails
     */
    @Override
    public Key engineGetKey(String alias, char[] password) {
        if (alias.equalsIgnoreCase("sms-transport-key")
            || alias.equalsIgnoreCase("sms.transport.key")) {
            return getTransportKey("sms-transport-key");
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

    private Key getTransportKey(String alias) {
        SecretBundle bundle = vaultService.getSecretByAlias(alias);
        if (bundle != null) {
            // decode the base64 encoded string
            byte[] decodedKey = Base64.getDecoder().decode(bundle.value());
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
    public Certificate[] engineGetCertificateChain(String alias) {
        throw new UnsupportedOperationException();
    }

    /**
     * @should return certificate when vault contains the certificate
     * @should return null when vault does not contain the alias
     */
    @Override
    public Certificate engineGetCertificate(String alias) {
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
    public Date engineGetCreationDate(String alias) {
        throw new UnsupportedOperationException();
    }

    /**
     * @should call Delegate
     */
    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) {
        vaultService.setKeyByAlias(alias, key);
    }

    /**
     * @should throw exception
     */
    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) {
        throw new UnsupportedOperationException();
    }

    /**
     * @should throw exception
     */
    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) {
        throw new UnsupportedOperationException();
    }

    /**
     * @should Call Delegate
     */
    @Override
    public void engineDeleteEntry(String alias) {
        vaultService.deleteSecretByAlias(alias);
    }

    /**
     * @should return an empty enumeration
     */
    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(vaultService.engineAliases());
    }

    /**
     * @should return true when vault contains  certificate with the required alias
     * @should return true when vault contains a key with the required alias
     * @should return false when vault does not contain the alias
     */
    @Override
    public boolean engineContainsAlias(String alias) {
        if (alias.equalsIgnoreCase("sms.transport.key")) {
            alias = "sms-transport-key";
        }
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
     * @should return true if alias is within list
     * @should return false if alias is not within list
     */
    @Override
    public boolean engineIsKeyEntry(String alias) {
        List<String> aliases = vaultService.engineAliases();
        return aliases.stream().anyMatch(vaultAlias -> vaultAlias.equalsIgnoreCase(alias));
    }

    /**
     * @should return true if certificate is in keyvault
     * @should return false if certificate isn't in keyvault
     */
    @Override
    public boolean engineIsCertificateEntry(String alias) {
        return vaultService.getCertificateByAlias(alias) != null;
    }

    /**
     * @should return entry is certificate or entry is secret
     * @should return false if entry isn't in keyvault
     */
    @Override
    public boolean engineEntryInstanceOf(String alias,
                                         Class<? extends KeyStore.Entry> entryClass) {
        if (alias.equalsIgnoreCase("sms.transport.key")) {
            alias = "sms-transport-key";
        }
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
    public String engineGetCertificateAlias(Certificate cert) {
        throw new UnsupportedOperationException();
    }

    /**
     * does nothing
     */
    @Override
    public void engineStore(OutputStream stream, char[] password) {
        // Do nothing. Do not throw exceptions
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) {
        vaultService = KeyVaultService.getInstance();
    }
}
