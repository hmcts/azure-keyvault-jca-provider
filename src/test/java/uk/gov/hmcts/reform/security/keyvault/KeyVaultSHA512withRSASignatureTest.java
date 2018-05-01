package uk.gov.hmcts.reform.security.keyvault;

import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class KeyVaultSHA512withRSASignatureTest extends KeyVaultRSASignatureTest {

    @InjectMocks
    private KeyVaultRSASignature.SHA512withRSA keyVaultRSASignature;

    @Override
    protected KeyVaultRSASignature getMockInjectedSignature() {
        return keyVaultRSASignature;
    }

    @Override
    protected KeyVaultRSASignature loadSignatureWithDefaultConstructor() {
        return new KeyVaultRSASignature.SHA512withRSA();
    }
}
