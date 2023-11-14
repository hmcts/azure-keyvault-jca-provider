package uk.gov.hmcts.reform.vault.credential;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;
import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import reactor.core.publisher.Mono;

import java.util.concurrent.TimeUnit;

public class CachedClientSecretCredential implements TokenCredential {

    private final LoadingCache<TokenRequestContext, Mono<AccessToken>> delegate;

    public CachedClientSecretCredential(String tenantId, String clientId, String clientKey) {
        ClientSecretCredential clientSecretCredential = new ClientSecretCredentialBuilder()
            .tenantId(tenantId)
            .clientId(clientId)
            .clientSecret(clientKey)
            .maxRetry(3)
            .build();
        delegate = CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)
            .build(CacheLoader
                .from(clientSecretCredential::getToken));
    }

    public void invalidateTokenCache() {
        this.delegate.invalidateAll();
    }

    @Override
    public Mono<AccessToken> getToken(TokenRequestContext request) {
        return delegate.getUnchecked(request);
    }

    @Override
    public AccessToken getTokenSync(TokenRequestContext request) {
        return delegate.getUnchecked(request).block();
    }
}
