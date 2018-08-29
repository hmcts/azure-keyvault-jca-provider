package uk.gov.hmcts.reform.security.keyvault;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import com.microsoft.azure.keyvault.models.CertificateBundle;
import com.microsoft.azure.keyvault.models.KeyBundle;
import com.microsoft.azure.keyvault.models.KeyOperationResult;
import com.microsoft.azure.keyvault.webkey.JsonWebKeySignatureAlgorithm;

import java.net.MalformedURLException;
import java.security.ProviderException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

final class KeyVaultService {

    static final String BASE_URL_PROPERTY = "azure_key_vault_base_url";

    static final String CLIENT_ID_PROPERTY = "azure_client_id";

    static final String CLIENT_SECRET_PROPERTY = "azure_client_secret";

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
        baseUrl = System.getProperty(BASE_URL_PROPERTY);
        this.vaultClient = vaultClient;
        this.keyByAliasCache = keyByAliasCache;
        this.keyByIdentifierCache = keyByIdentifierCache;
        this.certificateByAliasCache = certificateByAliasCache;
    }

    private KeyVaultService() {
        baseUrl = System.getProperty(BASE_URL_PROPERTY);

        String clientId = System.getProperty(CLIENT_ID_PROPERTY);
        String clientSecret = System.getProperty(CLIENT_SECRET_PROPERTY);

        KeyVaultCredentials keyVaultCredentials = new KeyVaultCredentials() {
            @Override
            public String doAuthenticate(String authorization, String resource, String scope) {
                ExecutorService service = null;
                try {
                    service = Executors.newFixedThreadPool(1);
                    AuthenticationContext context = new AuthenticationContext(authorization, false, service);

                    ClientCredential credential = new ClientCredential(clientId, clientSecret);
                    Future<AuthenticationResult> future = context.acquireToken(resource, credential, null);
                    AuthenticationResult authenticationResult = future.get(30, TimeUnit.SECONDS);

                    return authenticationResult.getAccessToken();
                } catch (MalformedURLException | InterruptedException | ExecutionException | TimeoutException e) {
                    throw new ProviderException(e);
                } finally {
                    if (service != null) {
                        service.shutdown();
                    }
                }
            }
        };

        vaultClient = new KeyVaultClient(keyVaultCredentials);
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
