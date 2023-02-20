package uk.gov.hmcts.reform.security.keyvault;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class KeyVaultRSAPrivateKeyTest {

    private static final KeyVaultRSAPrivateKey PRIVATE_KEY = new KeyVaultRSAPrivateKey("id", "alg");

    /**
     * @verifies return a 2048-bit integer
     * @see KeyVaultRSAPrivateKey#getModulus()
     */
    @Test
    public void getModulus_shouldReturn2048bitInteger() {
        assertEquals(2048, PRIVATE_KEY.getModulus().bitLength());
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
