package uk.gov.hmcts.reform.security.keyvault;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.microsoft.azure.PagedList;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.models.CertificateBundle;
import com.microsoft.azure.keyvault.models.CertificateItem;
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
import java.security.KeyStoreException;
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

    private final LoadingCache<Object, List<String>> keyAliasCache;

    private final LoadingCache<Object, List<String>> certificateAliasCache;

    private final Map<String, String> vaultKeyToRequestKeyMappings;

    private static final String SMS_TRANSPORT_KEY_DASHES = "sms-transport-key";

    private static final String SMS_TRANSPORT_KEY_DOTS = "sms.transport.key";

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

        this.vaultKeyToRequestKeyMappings.put(SMS_TRANSPORT_KEY_DASHES, SMS_TRANSPORT_KEY_DOTS);

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

        keyAliasCache = CacheBuilder.newBuilder()
            .expireAfterWrite(24, TimeUnit.HOURS)
            .build(CacheLoader
                .from(this::callVaultForKeyAliases));

        certificateAliasCache = CacheBuilder.newBuilder()
            .expireAfterWrite(24, TimeUnit.HOURS)
            .build(CacheLoader
                .from(this::callKeyVaultForCertificateAliases));
    }

    protected KeyVaultClient getClient() {
        return this.vaultClient;
    }

    /**
     * @should call delegate
     */
    KeyBundle getKeyByAlias(final String alias) {
        final String theAlias = replaceDotsWithDashes(alias);
        return getFromCacheOrNull(keyByAliasCache::getUnchecked, theAlias);
    }

    /**
     * @should call delegate
     */
    SecretBundle getSecretByAlias(final String alias) {
        final String theAlias = replaceDotsWithDashes(alias);
        return getFromCacheOrNull(secretByAliasCache::getUnchecked, theAlias);
    }

    /**
     * @should call delegate if key is SecretKey
     * @should throw exception if setting secret fails
     * @should throw exception if getting key to check fails
     * @should throw exception if key is unsupported
     */
    public SecretBundle setKeyByAlias(final String alias, final Key key) throws KeyStoreException {
        final String theAlias = replaceDotsWithDashes(alias);
        if (key instanceof SecretKey) {
            System.out.println("Trying to save key into KeyVault with alias " + theAlias);
            final JsonWebKey jsonWebKey = JsonWebKey.fromAes((SecretKey) key);
            final SetSecretRequest secretRequest = new SetSecretRequest
                .Builder(baseUrl, theAlias, new String(jsonWebKey.k()))
                .build();
            SecretBundle result = this.vaultClient.setSecret(secretRequest);
            if (result == null) {
                throw new KeyStoreException("Result from KeyVault SET_SECRET was NULL for alias "
                    + theAlias);
            }
            result = this.getSecretByAlias(theAlias);
            if (result == null) {
                throw new KeyStoreException("Result from KeyVault GET_SECRET after SET_SECRET was NULL for alias "
                    + theAlias);
            }
            System.out.println("Saving " + theAlias + " into KeyVault was successful");
            return result;
        }
        throw new UnsupportedOperationException("Only SecretKey Operations have been implemented");
    }

    /**
     * @should call delegate and return parsed list
     */
    public List<String> engineKeyAliases() {
        return getFromCacheOrNull(keyAliasCache::getUnchecked, "all");
    }

    private List<String> callVaultForKeyAliases() {
        final List<String> allKeys = new ArrayList<>();

        final PagedList<SecretItem> secretItems = this.vaultClient.listSecrets(baseUrl);
        secretItems.loadAll();
        secretItems.forEach(item -> allKeys.add(parseAzureAliasString(item.id())));

        final PagedList<KeyItem> keyItems = this.vaultClient.listKeys(baseUrl);
        keyItems.loadAll();
        keyItems.forEach(item -> allKeys.add(parseAzureAliasString(item.kid())));

        return allKeys;
    }

    /**
     * @should call delegate and return parsed list
     */
    public List<String> engineCertificateAliases() {
        return getFromCacheOrNull(certificateAliasCache::getUnchecked, "all");
    }

    private List<String> callKeyVaultForCertificateAliases() {
        final List<String> allKeys = new ArrayList<>();

        final PagedList<CertificateItem> certificateItems = this.vaultClient.listCertificates(baseUrl);
        certificateItems.loadAll();
        certificateItems.forEach(item -> allKeys.add(parseAzureAliasString(item.id())));

        return allKeys;
    }

    private String parseAzureAliasString(final String id) {
        String parsedString = id;
        if (parsedString.contains("/secrets/")) {
            parsedString = parseUrlIDString(parsedString, "/secrets/");
        }
        if (parsedString.contains("/keys/")) {
            parsedString = parseUrlIDString(parsedString, "/keys/");
        }
        if (parsedString.contains("/certificates/")) {
            parsedString = parseUrlIDString(parsedString, "/certificates/");
        }
        if (vaultKeyToRequestKeyMappings.containsKey(parsedString)) {
            parsedString = vaultKeyToRequestKeyMappings.get(parsedString);
        }
        return parsedString;
    }

    private String parseUrlIDString(final String stringToParse, final String pathOfID) {
        String parsedString = stringToParse.substring(stringToParse.indexOf(pathOfID) + pathOfID.length());
        if (parsedString.contains("/")) {
            parsedString = parsedString.substring(0, parsedString.indexOf("/"));
        }
        return parsedString;
    }

    private String replaceDotsWithDashes(final String alias) {
        String result = alias;
        if (alias.contains(".")) {
            result = alias.replace(".", "-");
            if (!this.vaultKeyToRequestKeyMappings.keySet().contains(result)) {
                this.mapVaultKeyToRequestedKey(result, alias);
            }
        }
        return result;
    }

    /**
     * @should call delegate
     */
    public SecretBundle deleteSecretByAlias(final String alias) {
        final String theAlias = replaceDotsWithDashes(alias);
        this.secretByAliasCache.invalidate(theAlias);
        return this.vaultClient.deleteSecret(baseUrl, theAlias);
    }

    /**
     * @should call delegate
     */
    KeyBundle getKeyByIdentifier(final String keyIdentifier) {
        return getFromCacheOrNull(keyByIdentifierCache::getUnchecked, keyIdentifier);
    }

    /**
     * @should call delegate
     * @should return null if certificate is missing
     */
    CertificateBundle getCertificateByAlias(final String alias) {
        final String theAlias = replaceDotsWithDashes(alias);
        return getFromCacheOrNull(certificateByAliasCache::getUnchecked, theAlias);
    }

    private void mapVaultKeyToRequestedKey(final String vaultKey, final String requestedKey) {
        this.vaultKeyToRequestKeyMappings.put(vaultKey, requestedKey);
        this.keyAliasCache.refresh("all");
        this.certificateAliasCache.refresh("all");
    }

    private <T> T getFromCacheOrNull(final Function<String, T> cacheGet, final String key) {
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
    KeyOperationResult sign(final String keyIdentifier,
                            final JsonWebKeySignatureAlgorithm algorithm,
                            final byte[] digest) {
        return vaultClient.sign(keyIdentifier, algorithm, digest);
    }
}
