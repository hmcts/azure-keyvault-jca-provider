package uk.gov.hmcts.reform.vault.credential;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;
import reactor.core.publisher.Mono;

public class ClientSecretKeyVaultCredential implements TokenCredential {
//    private final String clientId;
//    private final String clientKey;
//
//    public ClientSecretKeyVaultCredential(String clientId, String clientKey) {
//        this.clientId = clientId;
//        this.clientKey = clientKey;
//    }
//
//    @Override
//    public String doAuthenticate(String authorization, String resource, String scope) {
//        AuthenticationResult token = getAccessTokenFromClientCredentials(authorization, resource, clientId, clientKey);
//        return token.getAccessToken();
//    }
//
//    private static AuthenticationResult getAccessTokenFromClientCredentials(String authorization,
//            String resource, String clientId, String clientKey) {
//        AuthenticationResult result;
//        ExecutorService service = null;
//        try {
//            service = Executors.newFixedThreadPool(1);
//            AuthenticationContext context = new AuthenticationContext(authorization, false, service);
//            ClientCredential credentials = new ClientCredential(clientId, clientKey);
//            Future<AuthenticationResult> future = context.acquireToken(resource, credentials, null);
//            result = future.get();
//        } catch (Exception e) {
//            throw new ProviderException(e);
//        } finally {
//            if (service != null) {
//                service.shutdown();
//            }
//        }
//
//        if (result == null) {
//            throw new RuntimeException("Client Secret Key Vault authentication result was null");
//        }
//        return result;
//    }

    @Override
    public Mono<AccessToken> getToken(TokenRequestContext request) {
        return null;
    }

    @Override
    public AccessToken getTokenSync(TokenRequestContext request) {
        return TokenCredential.super.getTokenSync(request);
    }
}
