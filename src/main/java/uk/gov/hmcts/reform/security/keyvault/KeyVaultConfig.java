package uk.gov.hmcts.reform.security.keyvault;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@EqualsAndHashCode
public class KeyVaultConfig {

    public static final String VAULT_BASE_URL = "azure_key_vault_base_url";
    public static final String VAULT_CLIENT_ID = "azure_client_id";
    public static final String VAULT_CLIENT_KEY = "azure_client_secret";

    public static final String VAULT_MSI_URL = "azure_key_vault_msi_url";
    public static final String VAULT_ERROR_MAX_RETRIES = "azure_key_vault_msi_error_retry_max_number";
    public static final String VAULT_ERROR_RETRY_INTERVAL_MILLIS = "azure_key_vault_msi_error_retry_interval_millis";

    private String vaultBaseUrl;

    private String vaultClientId;

    private String vaultClientKey;

    private String vaultMsiUrl;

    private int vaultErrorMaxRetries;

    private int vaultErrorRetryIntervalMillis;

    public KeyVaultConfig() {
        vaultBaseUrl = System.getProperty(VAULT_BASE_URL);
        vaultClientId = System.getProperty(VAULT_CLIENT_ID);
        vaultClientKey = System.getProperty(VAULT_CLIENT_KEY);
        vaultMsiUrl = System.getProperty(VAULT_MSI_URL);

        final String maxRetries = System.getProperty(VAULT_ERROR_MAX_RETRIES);
        if (maxRetries != null) {
            vaultErrorMaxRetries = Integer.valueOf(maxRetries);
        }

        final String retryInterval = System.getProperty(VAULT_ERROR_RETRY_INTERVAL_MILLIS);
        if (retryInterval != null) {
            vaultErrorRetryIntervalMillis = Integer.valueOf(retryInterval);
        }
    }
}
