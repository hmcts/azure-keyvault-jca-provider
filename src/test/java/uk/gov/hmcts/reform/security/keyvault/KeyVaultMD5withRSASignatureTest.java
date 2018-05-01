package uk.gov.hmcts.reform.security.keyvault;

import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class KeyVaultMD5withRSASignatureTest extends KeyVaultRSASignatureTest {

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
