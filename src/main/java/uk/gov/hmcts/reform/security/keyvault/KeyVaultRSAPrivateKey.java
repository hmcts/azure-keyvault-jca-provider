package uk.gov.hmcts.reform.security.keyvault;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.util.Random;

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
     * @should return a 2048-bit integer
     */
    @Override
    public BigInteger getModulus() {
        // AM 7.x disallows the use of keys with length < 2048 bits.
        //
        // As KeyVault does not give us the real private key, we are using a
        // dummy private key modulus to work around the length checks.
        return DUMMY_2048bit_MODULUS;
    }

    private static final BigInteger DUMMY_2048bit_MODULUS = BigInteger.probablePrime(2048, new Random());
}
