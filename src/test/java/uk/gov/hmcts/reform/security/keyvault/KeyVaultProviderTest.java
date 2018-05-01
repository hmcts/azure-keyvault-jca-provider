package uk.gov.hmcts.reform.security.keyvault;

import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyStore;
import java.security.Security;

import static org.junit.Assert.assertNotNull;

public class KeyVaultProviderTest {

    @BeforeClass
    public static void beforeClass() {
        Security.addProvider(new KeyVaultProvider());
    }

    /**
     * @verifies register a KeyVault keystore
     * @see KeyVaultProvider#setup()
     */
    @Test
    public void setup_shouldRegisterAKeyVaultKeystore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("KeyVault");
        assertNotNull(keyStore);
    }

}
