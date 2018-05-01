package uk.gov.hmcts.reform.security.keyvault;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.Collections;

public final class KeyVaultProvider extends Provider {

    static final String PROVIDER_NAME = "KeyVault";

    private static final String INFO = "KeyVault Security Provider v1.0 - JCA Bridge for Azure KeyVault";

    public KeyVaultProvider() {
        super(PROVIDER_NAME, 1.0D, INFO);

        setup();
    }

    /**
     * @should register a KeyVault keystore
     */
    private void setup() {
        // register algorithms in provider
        AccessController.doPrivileged((PrivilegedAction<Object>) () -> {

            put("Signature.MD2withRSA", KeyVaultRSASignature.MD2withRSA.class.getName());
            put("Signature.MD5withRSA", KeyVaultRSASignature.MD5withRSA.class.getName());
            put("Signature.SHA1withRSA", KeyVaultRSASignature.SHA1withRSA.class.getName());
            put("Signature.SHA224withRSA", KeyVaultRSASignature.SHA224withRSA.class.getName());
            put("Signature.SHA256withRSA", KeyVaultRSASignature.SHA256withRSA.class.getName());
            put("Signature.SHA384withRSA", KeyVaultRSASignature.SHA384withRSA.class.getName());
            put("Signature.SHA512withRSA", KeyVaultRSASignature.SHA512withRSA.class.getName());

            String rsaKeyClasses = KeyVaultRSAPrivateKey.class.getName();
            put("Signature.MD2withRSA SupportedKeyClasses", rsaKeyClasses);
            put("Signature.MD5withRSA SupportedKeyClasses", rsaKeyClasses);
            put("Signature.SHA1withRSA SupportedKeyClasses", rsaKeyClasses);
            put("Signature.SHA224withRSA SupportedKeyClasses", rsaKeyClasses);
            put("Signature.SHA256withRSA SupportedKeyClasses", rsaKeyClasses);
            put("Signature.SHA384withRSA SupportedKeyClasses", rsaKeyClasses);
            put("Signature.SHA512withRSA SupportedKeyClasses", rsaKeyClasses);

            putService(new Service(this, "KeyStore", "KeyVault",
                KeyVaultKeyStore.class.getName(), Collections.singletonList("KeyVault"), null));

            return null;
        });
    }


}
