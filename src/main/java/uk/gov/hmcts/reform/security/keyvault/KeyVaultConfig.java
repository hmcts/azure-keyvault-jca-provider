package uk.gov.hmcts.reform.security.keyvault;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@EqualsAndHashCode
public class KeyVaultConfig {

    protected static final String VAULT_BASE_URL = "azure_key_vault_base_url";
    protected static final String VAULT_CLIENT_ID = "azure_client_id";
    protected static final String VAULT_CLIENT_KEY = "azure_client_secret";

    protected static final String VAULT_MSI_URL = "azure_key_vault_msi_url";
    protected static final String VAULT_ERROR_MAX_RETRIES = "azure_key_vault_msi_error_retry_max_number";
    protected static final String VAULT_ERROR_RETRY_INTERVAL_MILLIS = "azure_key_vault_msi_error_retry_interval_millis";

    protected static final String DEFAULT_VAULT_ERROR_MAX_RETRIES = "3";
    protected static final String DEFAULT_VAULT_ERROR_RETRY_INTERVAL_MILLIS = "0";

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
        vaultErrorMaxRetries = Integer.valueOf(System.getProperty(VAULT_ERROR_MAX_RETRIES,
            DEFAULT_VAULT_ERROR_MAX_RETRIES));
        vaultErrorRetryIntervalMillis = Integer.valueOf(System.getProperty(VAULT_ERROR_RETRY_INTERVAL_MILLIS,
            DEFAULT_VAULT_ERROR_RETRY_INTERVAL_MILLIS));
    }
}
