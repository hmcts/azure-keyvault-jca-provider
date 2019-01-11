package uk.gov.hmcts.reform.vault.config;

public class KeyVaultConfigBuilder {

    public static final String VAULT_BASE_URL = "azure_key_vault_base_url";
    public static final String VAULT_CLIENT_ID = "azure_client_id";
    public static final String VAULT_CLIENT_KEY = "azure_client_secret";
    public static final String VAULT_MSI_URL = "azure_key_vault_msi_url";
    public static final String VAULT_ERROR_MAX_RETRIES = "azure_key_vault_msi_error_retry_max_number";
    public static final String VAULT_ERROR_RETRY_INTERVAL_MILLIS = "azure_key_vault_msi_error_retry_interval_millis";

    public KeyVaultConfigBuilder() {
    }

    public KeyVaultConfig build() {
        KeyVaultConfig config = new KeyVaultConfig();
        config.setVaultBaseUrl(getProperty(VAULT_BASE_URL));
        config.setVaultClientId(getProperty(VAULT_CLIENT_ID));
        config.setVaultClientKey(getProperty(VAULT_CLIENT_KEY));
        config.setVaultMsiUrl(getProperty(VAULT_MSI_URL));
        config.setVaultErrorMaxRetries(getIntProperty(VAULT_ERROR_MAX_RETRIES));
        config.setVaultErrorRetryIntervalMillis(getIntProperty(VAULT_ERROR_RETRY_INTERVAL_MILLIS));

        return config;
    }

    private String getProperty(String propertyName) {
        return System.getProperty(propertyName);
    }

    private int getIntProperty(String propertyName) {
        String propertyValue = System.getProperty(propertyName);
        if (propertyValue != null) {
            return  Integer.valueOf(propertyValue);
        }

        return 0;
    }
}

