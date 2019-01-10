package uk.gov.hmcts.reform.security.keyvault;

import com.microsoft.azure.keyvault.KeyVaultClient;

public interface KeyVaultClientProvider {

    KeyVaultClient getClient(KeyVaultConfig keyVaultConfig);

}

