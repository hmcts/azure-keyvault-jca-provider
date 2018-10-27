package uk.gov.hmcts.reform.security.keyvault;

import com.microsoft.azure.keyvault.models.CertificateBundle;
import com.microsoft.azure.keyvault.models.KeyBundle;
import com.microsoft.azure.keyvault.webkey.JsonWebKey;
import com.microsoft.azure.keyvault.webkey.JsonWebKeyType;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreSpi;
import java.security.ProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;

public final class KeyVaultKeyStore extends KeyStoreSpi {

    private KeyVaultService vaultService;

    /**
     * @should return rsa private key for rsa alias
     * @should throw provider exception for unsupported key type
     * @should throw provider exception for secret key
     */
    @Override
    public Key engineGetKey(String alias, char[] password) {
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
            // TODO may need to support this functionality in the future
            throw new ProviderException("Secret-based keys are not implemented");
        }
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
     * @should throw exception
     */
    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) {
        throw new UnsupportedOperationException();
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
     * @should throw exception
     */
    @Override
    public void engineDeleteEntry(String alias) {
        throw new UnsupportedOperationException();
    }

    /**
     * @should return an empty enumeration
     */
    @Override
    public Enumeration<String> engineAliases() {
        return Collections.emptyEnumeration();
    }

    /**
     * @should return true when vault contains the certificate
     * @should return false when vault does not contain the alias
     */
    @Override
    public boolean engineContainsAlias(String alias) {
        try {
            return vaultService.getKeyByAlias(alias) != null || vaultService.getCertificateByAlias(alias) != null;
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
     * @should throw exception
     */
    @Override
    public boolean engineIsKeyEntry(String alias) {
        throw new UnsupportedOperationException();
    }

    /**
     * @should throw exception
     */
    @Override
    public boolean engineIsCertificateEntry(String alias) {
        throw new UnsupportedOperationException();
    }

    /**
     * @should throw exception
     */
    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        throw new UnsupportedOperationException();
    }

    /**
     * @should throw exception
     */
    @Override
    public void engineStore(OutputStream stream, char[] password) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) {
        vaultService = KeyVaultService.getInstance();
    }
}
