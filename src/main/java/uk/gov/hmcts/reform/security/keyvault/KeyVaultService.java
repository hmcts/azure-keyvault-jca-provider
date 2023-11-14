package uk.gov.hmcts.reform.security.keyvault;

import com.azure.core.credential.TokenCredential;
import com.azure.core.http.rest.PagedIterable;
import com.azure.core.util.polling.PollResponse;
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.CertificateClientBuilder;
import com.azure.security.keyvault.certificates.models.CertificateProperties;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificateWithPolicy;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.SignResult;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import com.azure.security.keyvault.keys.models.JsonWebKey;
import com.azure.security.keyvault.keys.models.KeyProperties;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.DeletedSecret;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.azure.security.keyvault.secrets.models.SecretProperties;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import lombok.AllArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import uk.gov.hmcts.reform.vault.config.KeyVaultConfig;
import uk.gov.hmcts.reform.vault.credential.CachedClientSecretCredential;
import uk.gov.hmcts.reform.vault.credential.CachedDefaultAzureCredential;

import java.security.Key;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;

final class KeyVaultService {
    private static volatile KeyVaultService INSTANCE;

    private KeyClient keyClient;

    private SecretClient secretClient;

    private CertificateClient certificateClient;

    private final LoadingCache<String, KeyVaultSecret> secretByAliasCache;

    private final LoadingCache<String, KeyVaultKey> keyByAliasCache;

    private final LoadingCache<String, KeyVaultCertificateWithPolicy> certificateByAliasCache;

    private final LoadingCache<Object, List<String>> keyAliasCache;

    private final LoadingCache<Object, List<String>> certificateAliasCache;

    private final Map<String, String> vaultKeyToRequestKeyMappings;

    private final TokenCredential tokenCredential;

    private static final String SMS_TRANSPORT_KEY_DASHES = "sms-transport-key";

    private static final String SMS_TRANSPORT_KEY_DOTS = "sms.transport.key";

    /**
     * @should produce an instance
     */
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
        this(new SystemPropertyKeyVaultConfigBuilder().build(), null);
    }

    KeyVaultService(KeyVaultConfig keyVaultConfig, ClientHolder holder) {
        if (StringUtils.isNoneEmpty(keyVaultConfig.getVaultTenantId(),
            keyVaultConfig.getVaultClientId(), keyVaultConfig.getVaultClientKey())) {
            tokenCredential =
                new CachedClientSecretCredential(
                    keyVaultConfig.getVaultTenantId(),
                    keyVaultConfig.getVaultClientId(),
                    keyVaultConfig.getVaultClientKey());
        } else {
            tokenCredential = new CachedDefaultAzureCredential();
        }

        KeyClientBuilder keyClientBuilder = new KeyClientBuilder();
        SecretClientBuilder secretClientBuilder = new SecretClientBuilder();
        CertificateClientBuilder certificateClientBuilder = new CertificateClientBuilder();

        keyClientBuilder.vaultUrl(keyVaultConfig.getVaultBaseUrl())
            .credential(tokenCredential);
        secretClientBuilder.vaultUrl(keyVaultConfig.getVaultBaseUrl())
            .credential(tokenCredential);
        certificateClientBuilder.vaultUrl(keyVaultConfig.getVaultBaseUrl())
            .credential(tokenCredential);

        this.keyClient = keyClientBuilder.buildClient();
        this.secretClient = secretClientBuilder.buildClient();
        this.certificateClient = certificateClientBuilder.buildClient();

        if (holder != null) {
            // for testing
            this.keyClient = holder.keyClient;
            this.secretClient = holder.secretClient;
            this.certificateClient = holder.certificateClient;
        }

        this.vaultKeyToRequestKeyMappings = new ConcurrentHashMap<>();

        this.vaultKeyToRequestKeyMappings.put(SMS_TRANSPORT_KEY_DASHES, SMS_TRANSPORT_KEY_DOTS);

        keyAliasCache = CacheBuilder.newBuilder()
            .expireAfterWrite(24, TimeUnit.HOURS)
            .build(CacheLoader
                .from(this::callVaultForKeyAliases));

        secretByAliasCache = CacheBuilder.newBuilder()
            .expireAfterWrite(24, TimeUnit.HOURS)
            .build(CacheLoader
                .from(secretClient::getSecret));

        keyByAliasCache = CacheBuilder.newBuilder()
            .expireAfterWrite(24, TimeUnit.HOURS)
            .build(CacheLoader
                .from(keyClient::getKey));

        certificateAliasCache = CacheBuilder.newBuilder()
            .expireAfterWrite(24, TimeUnit.HOURS)
            .build(CacheLoader
                .from(this::callKeyVaultForCertificateAliases));

        certificateByAliasCache = CacheBuilder.newBuilder()
            .expireAfterWrite(24, TimeUnit.HOURS)
            .build(CacheLoader
                .from(certificateClient::getCertificate));
    }

    ClientHolder getClients() {
        return new ClientHolder(secretClient, keyClient, certificateClient);
    }

    /**
     * @should call delegate
     */
    KeyVaultKey getKeyByAlias(final String alias) {
        final String theAlias = replaceDotsWithDashes(alias);
        return getFromCacheOrNull(keyByAliasCache::getUnchecked, theAlias);
    }

    /**
     * @should call delegate
     */
    KeyVaultSecret getSecretByAlias(final String alias) {
        final String theAlias = replaceDotsWithDashes(alias);
        return getFromCacheOrNull(secretByAliasCache::getUnchecked, theAlias);
    }

    /**
     * @should call delegate if key is SecretKey
     * @should throw exception if setting secret fails
     * @should throw exception if getting key to check fails
     * @should throw exception if key is unsupported
     */
    public KeyVaultSecret setKeyByAlias(final String alias, final Key key) throws KeyStoreException {
        final String theAlias = replaceDotsWithDashes(alias);
        if (key instanceof SecretKey) {
            System.out.println("Trying to save key into KeyVault with alias " + theAlias);
            final JsonWebKey jsonWebKey = JsonWebKey.fromAes((SecretKey) key);
            final KeyVaultSecret secretRequest = new KeyVaultSecret(theAlias, new String(jsonWebKey.getK()));
            boolean success = false;
            KeyVaultSecret result = null;
            while (!success) {
                try {
                    this.secretClient.purgeDeletedSecret(theAlias);
                    System.out.println("Purged secret from deleted state. Sleeping 10s");
                    Thread.sleep(10000);
                } catch (Exception e) {
                    System.out.println("Failed while attempting to purge " + theAlias + " before saving: "
                        + "\nmessage  : " + e.getMessage()
                        + "\ncontinuing to set secret value.");
                }
                try {
                    Thread.sleep(1000);
                    result = this.secretClient.setSecret(secretRequest);
                } catch (Exception e) {
                    System.out.println("Failed while trying save " + theAlias + ": "
                        + "\nmessage  : " + e.getMessage()
                        + "\nRetrying.");
                    continue;
                }
                success = true;
            }
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
        throw new UnsupportedOperationException("Only SecretKey Operations have been implemented : " + alias);
    }

    /**
     * @should call delegate and return parsed list
     */
    public List<String> engineKeyAliases() {
        return getFromCacheOrNull(keyAliasCache::getUnchecked, "all");
    }

    private List<String> callVaultForKeyAliases() {
        final List<String> allKeys = new ArrayList<>();

        final PagedIterable<String> secretItems = this.secretClient
            .listPropertiesOfSecrets()
            .mapPage((SecretProperties::getName));
        secretItems.stream().collect(Collectors.toList())
            .forEach(item -> allKeys.add(parseAzureAliasString(item)));

        final PagedIterable<String> keyItems = this.keyClient
            .listPropertiesOfKeys()
            .mapPage((KeyProperties::getName));
        keyItems.stream().collect(Collectors.toList())
            .forEach(item -> allKeys.add(parseAzureAliasString(item)));

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

        final PagedIterable<String> certificateItems = this.certificateClient
            .listPropertiesOfCertificates()
            .mapPage((CertificateProperties::getName));
        certificateItems.stream().collect(Collectors.toList())
            .forEach(item -> allKeys.add(parseAzureAliasString(item)));

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
            if (!this.vaultKeyToRequestKeyMappings.containsKey(result)) {
                System.out.println("Replacing dots with dashes : " + alias
                                       + " " + result);
                this.mapVaultKeyToRequestedKey(result, alias);
            }
        }
        return result;
    }

    /**
     * @should call delegate
     */
    public DeletedSecret deleteSecretByAlias(final String alias) {
        final String theAlias = replaceDotsWithDashes(alias);
        this.secretByAliasCache.invalidate(theAlias);
        PollResponse<DeletedSecret> bundle = this.secretClient
            .beginDeleteSecret(theAlias)
            .waitForCompletion();
        this.secretClient.purgeDeletedSecret(theAlias);
        return bundle.getValue();
    }

    /**
     * @should call delegate
     * @should return null if certificate is missing
     */
    KeyVaultCertificateWithPolicy getCertificateByAlias(final String alias) {
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
     * @should invalidate cache and call delegate again
     */
    SignResult sign(final String keyIdentifier,
                    final SignatureAlgorithm algorithm,
                    final byte[] digest) {
        try {
            return buildClientAndSign(keyIdentifier, algorithm, digest);
        } catch (Exception e) {
            System.out.println("Exception was thrown during signing :"
                + "\nname     : " + e.getClass()
                + "\nmessage  : " + e.getMessage()
                + "\ninvalidating token cache and retrying.");
            if (tokenCredential instanceof CachedDefaultAzureCredential) {
                ((CachedDefaultAzureCredential) tokenCredential).invalidateTokenCache();
            }
            return this.buildClientAndSign(keyIdentifier, algorithm, digest);
        }
    }

    private SignResult buildClientAndSign(String keyIdentifier, SignatureAlgorithm algorithm, byte[] digest) {
        return new CryptographyClientBuilder()
            .credential(tokenCredential)
            .keyIdentifier(keyIdentifier)
            .buildClient()
            .sign(algorithm, digest);
    }

    @AllArgsConstructor
    public static final class ClientHolder {
        public final SecretClient secretClient;
        public final KeyClient keyClient;
        public final CertificateClient certificateClient;
    }
}
