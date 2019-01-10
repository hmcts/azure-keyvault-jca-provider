package uk.gov.hmcts.reform.vault.config;

import com.microsoft.azure.keyvault.KeyVaultClient;
import uk.gov.hmcts.reform.vault.config.KeyVaultConfig;

public interface KeyVaultClientProvider {

    KeyVaultClient getClient(KeyVaultConfig keyVaultConfig);

}

