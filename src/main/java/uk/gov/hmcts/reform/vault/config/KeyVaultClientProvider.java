package uk.gov.hmcts.reform.vault.config;

import com.microsoft.azure.keyvault.KeyVaultClient;

public interface KeyVaultClientProvider {

    KeyVaultClient getClient(KeyVaultConfig keyVaultConfig);

}

