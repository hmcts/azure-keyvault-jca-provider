package uk.gov.hmcts.reform.vault.credential;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;
import com.azure.identity.DefaultAzureCredential;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import reactor.core.publisher.Mono;

import java.util.concurrent.TimeUnit;

public class CachedDefaultAzureCredential implements TokenCredential {

    private final LoadingCache<TokenRequestContext, Mono<AccessToken>> delegate;

    public CachedDefaultAzureCredential() {
        DefaultAzureCredential defaultAzureCredential = new DefaultAzureCredentialBuilder()
            .maxRetry(3)
            .build();
        delegate = CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)
            .build(CacheLoader
                .from(defaultAzureCredential::getToken));
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
