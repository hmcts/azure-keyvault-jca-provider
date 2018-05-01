package uk.gov.hmcts.reform.security.keyvault;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class KeyVaultKeyTest {

    /**
     * @verifies return identifier
     * @see KeyVaultKey#getIdentifier()
     */
    @Test
    public void getIdentifier_shouldReturnIdentifier() {
        String id = "id";
        assertEquals(id, new KeyVaultRSAPrivateKey(id, null).getIdentifier());
    }

    /**
     * @verifies return algorithm
     * @see KeyVaultKey#getAlgorithm()
     */
    @Test
    public void getAlgorithm_shouldReturnAlgorithm() {
        String alg = "RSA";
        assertEquals(alg, new KeyVaultRSAPrivateKey(null, alg).getAlgorithm());
    }
}
