package uk.gov.hmcts.reform.security.keyvault;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.models.CertificateBundle;
import com.microsoft.azure.keyvault.models.KeyBundle;
import com.microsoft.azure.keyvault.models.KeyOperationResult;
import com.microsoft.azure.keyvault.webkey.JsonWebKeySignatureAlgorithm;
import org.apache.commons.lang3.StringUtils;
import uk.gov.hmcts.reform.security.keyvault.credential.AccessTokenKeyVaultCredential;
import uk.gov.hmcts.reform.security.keyvault.credential.ClientSecretKeyVaultCredential;

import java.util.concurrent.TimeUnit;


final class KeyVaultService {
    private static final KeyVaultService INSTANCE = new KeyVaultService();

    private final String baseUrl;

    private final KeyVaultClient vaultClient;

    private final LoadingCache<String, KeyBundle> keyByAliasCache;

    private final LoadingCache<String, KeyBundle> keyByIdentifierCache;

    private final LoadingCache<String, CertificateBundle> certificateByAliasCache;

    public static KeyVaultService getInstance() {
        return INSTANCE;
    }

    // Used by tests to inject the vault client
    KeyVaultService(KeyVaultClient vaultClient, LoadingCache<String, KeyBundle> keyByAliasCache, LoadingCache<String,
        KeyBundle> keyByIdentifierCache, LoadingCache<String, CertificateBundle> certificateByAliasCache) {
        baseUrl = System.getProperty(KeyVaultConfig.VAULT_BASE_URL);
        this.vaultClient = vaultClient;
        this.keyByAliasCache = keyByAliasCache;
        this.keyByIdentifierCache = keyByIdentifierCache;
        this.certificateByAliasCache = certificateByAliasCache;
    }

    private KeyVaultService() {
        baseUrl = System.getProperty(KeyVaultConfig.VAULT_BASE_URL);

        vaultClient = getClient(new KeyVaultConfig());

        // TODO Handle null vaultClient;

        keyByAliasCache = CacheBuilder.newBuilder()
            .expireAfterWrite(24, TimeUnit.HOURS)
            .build(new KeyByAliasCacheLoader(baseUrl, vaultClient));
        keyByIdentifierCache = CacheBuilder.newBuilder()
            .expireAfterWrite(24, TimeUnit.HOURS)
            .build(new KeyByIdentifierCacheLoader(vaultClient));
        certificateByAliasCache = CacheBuilder.newBuilder()
            .expireAfterWrite(24, TimeUnit.HOURS)
            .build(new CertificateByAliasCacheLoader(baseUrl, vaultClient));
    }

    /**
     * @should select correct client based on system properties
     */
    public KeyVaultClient getClient(KeyVaultConfig keyVaultConfig) {
        if (StringUtils.isNoneEmpty(keyVaultConfig.getVaultClientId(), keyVaultConfig.getVaultClientKey())) {
            return new KeyVaultClient(new ClientSecretKeyVaultCredential(keyVaultConfig.getVaultClientId(),
                    keyVaultConfig.getVaultClientKey()));
        } else if (StringUtils.isNotEmpty(keyVaultConfig.getVaultMsiUrl())) {
            return new KeyVaultClient(new AccessTokenKeyVaultCredential(keyVaultConfig.getVaultMsiUrl()));
        }
        return null;
    }

    /**
     * @should call delegate
     */
    KeyBundle getKeyByAlias(String alias) {
        return keyByAliasCache.getUnchecked(alias);
    }

    /**
     * @should call delegate
     */
    KeyBundle getKeyByIdentifier(String keyIdentifier) {
        return keyByIdentifierCache.getUnchecked(keyIdentifier);
    }

    /**
     * @should call delegate
     */
    CertificateBundle getCertificateByAlias(String alias) {
        return certificateByAliasCache.getUnchecked(alias);
    }

    /**
     * @should call delegate
     */
    KeyOperationResult sign(String keyIdentifier, JsonWebKeySignatureAlgorithm algorithm, byte[] digest) {
        return vaultClient.sign(keyIdentifier, algorithm, digest);
    }

    static final class KeyByAliasCacheLoader extends CacheLoader<String, KeyBundle> {

        private final String baseUrl;

        private final KeyVaultClient vaultClient;

        KeyByAliasCacheLoader(String baseUrl, KeyVaultClient vaultClient) {
            this.baseUrl = baseUrl;
            this.vaultClient = vaultClient;
        }

        @Override
        public KeyBundle load(String alias) {
            KeyBundle key = vaultClient.getKey(baseUrl, alias);
            if (key == null) {
                throw new NullPointerException();
            }
            return key;
        }
    }

    static final class KeyByIdentifierCacheLoader extends CacheLoader<String, KeyBundle> {

        private final KeyVaultClient vaultClient;

        KeyByIdentifierCacheLoader(KeyVaultClient vaultClient) {
            this.vaultClient = vaultClient;
        }

        @Override
        public KeyBundle load(String keyIdentifier) {
            KeyBundle key = vaultClient.getKey(keyIdentifier);
            if (key == null) {
                throw new NullPointerException();
            }
            return key;
        }
    }

    static final class CertificateByAliasCacheLoader extends CacheLoader<String, CertificateBundle> {

        private final String baseUrl;

        private final KeyVaultClient vaultClient;

        CertificateByAliasCacheLoader(String baseUrl, KeyVaultClient vaultClient) {
            this.baseUrl = baseUrl;
            this.vaultClient = vaultClient;
        }

        @Override
        public CertificateBundle load(String alias) {
            CertificateBundle certificate = vaultClient.getCertificate(baseUrl, alias);
            if (certificate == null) {
                throw new NullPointerException();
            }
            return certificate;
        }
    }
}
