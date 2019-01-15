package uk.gov.hmcts.reform.security.keyvault;

import uk.gov.hmcts.reform.vault.config.KeyVaultConfig;

public class SystemPropertyKeyVaultConfigBuilder {

    public static final String DEFAULT_VAULT_MSI_URL = "http://169.254.169.254/metadata/identity/oauth2/"
        + "token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net";

    public static final String DEFAULT_VAULT_ERROR_MAX_RETRIES = "0";

    public static final String DEFAULT_VAULT_ERROR_RETRY_INTERVAL_MILLIS = "200";

    public static final String VAULT_BASE_URL = "azure_key_vault_base_url";
    public static final String VAULT_CLIENT_ID = "azure_client_id";
    public static final String VAULT_CLIENT_KEY = "azure_client_secret";
    public static final String VAULT_MSI_URL = "azure_key_vault_msi_url";
    public static final String VAULT_ERROR_MAX_RETRIES = "azure_key_vault_msi_error_retry_max_number";
    public static final String VAULT_ERROR_RETRY_INTERVAL_MILLIS = "azure_key_vault_msi_error_retry_interval_millis";

    public SystemPropertyKeyVaultConfigBuilder() {
    }

    public KeyVaultConfig build() {
        KeyVaultConfig config = new KeyVaultConfig();
        config.setVaultBaseUrl(System.getProperty(VAULT_BASE_URL));
        config.setVaultClientId(System.getProperty(VAULT_CLIENT_ID));
        config.setVaultClientKey(System.getProperty(VAULT_CLIENT_KEY));
        config.setVaultMsiUrl(System.getProperty(VAULT_MSI_URL, DEFAULT_VAULT_MSI_URL));
        config.setVaultErrorMaxRetries(Integer.valueOf(System.getProperty(VAULT_ERROR_MAX_RETRIES,
            DEFAULT_VAULT_ERROR_MAX_RETRIES)));
        config.setVaultErrorRetryIntervalMillis(Integer.valueOf(System.getProperty(VAULT_ERROR_RETRY_INTERVAL_MILLIS,
            DEFAULT_VAULT_ERROR_RETRY_INTERVAL_MILLIS)));

        return config;
    }
}

