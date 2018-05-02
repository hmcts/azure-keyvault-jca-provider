package uk.gov.hmcts.reform.security.keyvault;

import org.junit.Test;

public class KeyVaultRSAPrivateKeyTest {

    private static final KeyVaultRSAPrivateKey PRIVATE_KEY = new KeyVaultRSAPrivateKey("id", "alg");

    /**
     * @verifies throw exception
     * @see KeyVaultRSAPrivateKey#getModulus()
     */
    @Test(expected = UnsupportedOperationException.class)
    public void getModulus_shouldThrowException() {
        PRIVATE_KEY.getModulus();
    }

    /**
     * @verifies throw exception
     * @see KeyVaultRSAPrivateKey#getEncodedInternal()
     */
    @Test(expected = UnsupportedOperationException.class)
    public void getEncodedInternal_shouldThrowException() {
        PRIVATE_KEY.getEncodedInternal();
    }

    /**
     * @verifies throw exception
     * @see KeyVaultRSAPrivateKey#getPrivateExponent()
     */
    @Test(expected = UnsupportedOperationException.class)
    public void getPrivateExponent_shouldThrowException() {
        PRIVATE_KEY.getPrivateExponent();
    }

    /**
     * @verifies throw exception
     * @see KeyVaultRSAPrivateKey#getFormat()
     */
    @Test(expected = UnsupportedOperationException.class)
    public void getFormat_shouldThrowException() {
        PRIVATE_KEY.getFormat();
    }
}
