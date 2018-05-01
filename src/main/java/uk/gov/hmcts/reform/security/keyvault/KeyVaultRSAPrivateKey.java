package uk.gov.hmcts.reform.security.keyvault;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

final class KeyVaultRSAPrivateKey extends KeyVaultKey implements RSAPrivateKey {

    KeyVaultRSAPrivateKey(String identifier, String algorithm) {
        super(identifier, algorithm);
    }

    /**
     * @should throw exception
     */
    @Override
    byte[] getEncodedInternal() {
        throw new UnsupportedOperationException();
    }

    /**
     * @should throw exception
     */
    @Override
    public BigInteger getPrivateExponent() {
        throw new UnsupportedOperationException();
    }

    /**
     * @should throw exception
     */
    @Override
    public String getFormat() {
        throw new UnsupportedOperationException();
    }

    /**
     * @should throw exception
     */
    @Override
    public BigInteger getModulus() {
        throw new UnsupportedOperationException();
    }
}
