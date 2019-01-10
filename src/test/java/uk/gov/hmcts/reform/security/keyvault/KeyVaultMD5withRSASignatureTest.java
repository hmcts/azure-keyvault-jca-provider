package uk.gov.hmcts.reform.security.keyvault;

import org.junit.Before;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.junit.MockitoJUnitRunner;
import uk.gov.hmcts.reform.vault.config.KeyVaultConfig;

@RunWith(MockitoJUnitRunner.class)
public class KeyVaultMD5withRSASignatureTest extends KeyVaultRSASignatureTest {

    @Before
    public void setUp() {
        System.setProperty(KeyVaultConfig.VAULT_BASE_URL, "BASE_URL");
        System.setProperty(KeyVaultConfig.VAULT_CLIENT_ID, "CLIENT_ID");
        System.setProperty(KeyVaultConfig.VAULT_CLIENT_KEY, "CLIENT_KEY");
    }

    @InjectMocks
    private KeyVaultRSASignature.MD5withRSA signature;

    @Override
    protected KeyVaultRSASignature getMockInjectedSignature() {
        return signature;
    }

    @Override
    protected KeyVaultRSASignature loadSignatureWithDefaultConstructor() {
        return new KeyVaultRSASignature.MD5withRSA();
    }
}
