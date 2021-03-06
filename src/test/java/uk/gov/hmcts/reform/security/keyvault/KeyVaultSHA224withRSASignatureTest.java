package uk.gov.hmcts.reform.security.keyvault;

import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class KeyVaultSHA224withRSASignatureTest extends KeyVaultRSASignatureTest {

    @InjectMocks
    private KeyVaultRSASignature.SHA224withRSA signature;

    @Override
    protected KeyVaultRSASignature getMockInjectedSignature() {
        return signature;
    }

    @Override
    protected KeyVaultRSASignature loadSignatureWithDefaultConstructor() {
        return new KeyVaultRSASignature.SHA224withRSA();
    }
}
