package uk.gov.hmcts.reform.security.keyvault;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.microsoft.azure.PagedList;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.models.CertificateBundle;
import com.microsoft.azure.keyvault.models.KeyBundle;
import com.microsoft.azure.keyvault.models.KeyItem;
import com.microsoft.azure.keyvault.models.KeyOperationResult;
import com.microsoft.azure.keyvault.models.SecretBundle;
import com.microsoft.azure.keyvault.models.SecretItem;
import com.microsoft.azure.keyvault.requests.SetSecretRequest;
import com.microsoft.azure.keyvault.webkey.JsonWebKey;
import com.microsoft.azure.keyvault.webkey.JsonWebKeySignatureAlgorithm;
import org.apache.commons.lang3.StringUtils;
import uk.gov.hmcts.reform.vault.config.KeyVaultClientProvider;
import uk.gov.hmcts.reform.vault.config.KeyVaultConfig;
import uk.gov.hmcts.reform.vault.credential.AccessTokenKeyVaultCredential;
import uk.gov.hmcts.reform.vault.credential.ClientSecretKeyVaultCredential;

import java.security.Key;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import javax.crypto.SecretKey;

final class KeyVaultService {
    private static volatile KeyVaultService INSTANCE;

    private final String baseUrl;

    private final KeyVaultClient vaultClient;

    private final LoadingCache<String, SecretBundle> secretByAliasCache;

    private final LoadingCache<String, KeyBundle> keyByAliasCache;

    private final LoadingCache<String, KeyBundle> keyByIdentifierCache;

    private final LoadingCache<String, CertificateBundle> certificateByAliasCache;

    private final Map<String, String> vaultKeyToRequestKeyMappings;

    public static KeyVaultService getInstance() {
        if (INSTANCE == null) {
            synchronized (KeyVaultService.class) {
                if (INSTANCE == null) {
                    INSTANCE = new KeyVaultService();
                }
            }
        }

        return INSTANCE;
    }

    private KeyVaultService() {
        this(new SystemPropertyKeyVaultConfigBuilder().build());
    }

    KeyVaultService(KeyVaultConfig keyVaultConfig) {
        this(keyVaultConfig, new KeyVaultClientProvider() {
            @Override
            public KeyVaultClient getClient(KeyVaultConfig keyVaultConfig) {
                if (StringUtils.isNoneEmpty(keyVaultConfig.getVaultClientId(), keyVaultConfig.getVaultClientKey())) {
                    return new KeyVaultClient(new ClientSecretKeyVaultCredential(keyVaultConfig.getVaultClientId(),
                        keyVaultConfig.getVaultClientKey()));
                } else if (StringUtils.isNotEmpty(keyVaultConfig.getVaultMsiUrl())) {
                    return new KeyVaultClient(new AccessTokenKeyVaultCredential(keyVaultConfig.getVaultMsiUrl(),
                        keyVaultConfig.getVaultErrorMaxRetries(), keyVaultConfig.getVaultErrorRetryIntervalMillis()));
                }

                throw new IllegalArgumentException("System properties do not define which KeyVaultClient to create");
            }
        }.getClient(keyVaultConfig));
    }

    KeyVaultService(KeyVaultConfig keyVaultConfig, KeyVaultClient vaultClient) {
        this.vaultClient = vaultClient;
        this.baseUrl = keyVaultConfig.getVaultBaseUrl();
        this.vaultKeyToRequestKeyMappings = new ConcurrentHashMap<>();

        secretByAliasCache = CacheBuilder.newBuilder()
            .expireAfterWrite(24, TimeUnit.HOURS)
            .build(CacheLoader
                .from((String alias) -> vaultClient.getSecret(baseUrl, alias)));

        keyByAliasCache = CacheBuilder.newBuilder()
            .expireAfterWrite(24, TimeUnit.HOURS)
            .build(CacheLoader
                .from((String alias) -> vaultClient.getKey(baseUrl, alias)));

        keyByIdentifierCache = CacheBuilder.newBuilder()
            .expireAfterWrite(24, TimeUnit.HOURS)
            .build(CacheLoader
                .from(vaultClient::getKey));

        certificateByAliasCache = CacheBuilder.newBuilder()
            .expireAfterWrite(24, TimeUnit.HOURS)
            .build(CacheLoader
                .from((String alias) -> vaultClient.getCertificate(baseUrl, alias)));
    }

    protected KeyVaultClient getClient() {
        return this.vaultClient;
    }

    /**
     * @should call delegate
     */
    KeyBundle getKeyByAlias(String alias) {
        alias = replaceDotsWithDashes(alias);
        return getFromCacheOrNull(keyByAliasCache::getUnchecked, alias);
    }

    /**
     * @should call delegate
     */
    SecretBundle getSecretByAlias(String alias) {
        alias = replaceDotsWithDashes(alias);
        return getFromCacheOrNull(secretByAliasCache::getUnchecked, alias);
    }

    /**
     * @should call delegate if key is SecretKey
     * @should throw exception if key is unsupported
     */
    public SecretBundle setKeyByAlias(String alias, Key key) {
        alias = replaceDotsWithDashes(alias);
        if (key instanceof SecretKey) {
            JsonWebKey jsonWebKey = JsonWebKey.fromAes((SecretKey) key);
            SetSecretRequest secretRequest = new SetSecretRequest
                .Builder(baseUrl, alias, new String(jsonWebKey.k()))
                .build();
            return this.vaultClient.setSecret(secretRequest);
        }
        throw new UnsupportedOperationException("Only SecretKey Operations have been implemented");
    }

    /**
     * @should call delegate and return parsed list
     */
    public List<String> engineAliases() {
        List<String> allKeys = new ArrayList<>();
        PagedList<SecretItem> secretItems = this.vaultClient.listSecrets(baseUrl);
        secretItems.forEach(item -> allKeys.add(parseAzureAliasString(item.id())));
        PagedList<KeyItem> keyItems = this.vaultClient.listKeys(baseUrl);
        keyItems.forEach(item -> allKeys.add(parseAzureAliasString(item.kid())));
        return allKeys;
    }

    private String parseAzureAliasString(String id) {
        String parsedString = id;
        if (parsedString.contains("/secrets/")) {
            parsedString = parseUrlIDString(parsedString, "/secrets/");
        }
        if (parsedString.contains("/keys/")) {
            parsedString = parseUrlIDString(parsedString, "/keys/");
        }
        if (vaultKeyToRequestKeyMappings.containsKey(parsedString)) {
            parsedString = vaultKeyToRequestKeyMappings.get(parsedString);
        }
        return parsedString;
    }

    private String replaceDotsWithDashes(String alias) {
        if (alias.contains(".")) {
            String dots = alias;
            alias = alias.replace(".", "-");
            this.mapVaultKeyToRequestedKey(alias, dots);
        }
        return alias;
    }

    private String parseUrlIDString(String stringToParse, String pathOfID) {
        String parsedString = stringToParse;
        parsedString = parsedString.substring(parsedString.indexOf(pathOfID) + pathOfID.length());
        if (parsedString.contains("/")) {
            parsedString = parsedString.substring(0, parsedString.indexOf("/"));
        }
        return parsedString;
    }

    /**
     * @should call delegate
     */
    public SecretBundle deleteSecretByAlias(String alias) {
        alias = replaceDotsWithDashes(alias);
        this.secretByAliasCache.invalidate(alias);
        return this.vaultClient.deleteSecret(baseUrl, alias);
    }

    /**
     * @should call delegate
     */
    KeyBundle getKeyByIdentifier(String keyIdentifier) {
        return getFromCacheOrNull(keyByIdentifierCache::getUnchecked, keyIdentifier);
    }

    /**
     * @should call delegate
     * @should return null if certificate is missing
     */
    CertificateBundle getCertificateByAlias(String alias) {
        alias = replaceDotsWithDashes(alias);
        return getFromCacheOrNull(certificateByAliasCache::getUnchecked, alias);
    }

    /**
     * @param vaultKey The name of the Key in Vault
     * @param requestedKey The name of the Key requested by App
     */
    public void mapVaultKeyToRequestedKey(String vaultKey, String requestedKey) {
        this.vaultKeyToRequestKeyMappings.put(vaultKey, requestedKey);
    }

    private <T> T getFromCacheOrNull(Function<String, T> cacheGet, String key) {
        T result;
        try {
            result = cacheGet.apply(key);
        } catch (Exception e) {
            result = null;
        }
        return result;
    }

    /**
     * @should call delegate
     */
    KeyOperationResult sign(String keyIdentifier, JsonWebKeySignatureAlgorithm algorithm, byte[] digest) {
        return vaultClient.sign(keyIdentifier, algorithm, digest);
    }
}
