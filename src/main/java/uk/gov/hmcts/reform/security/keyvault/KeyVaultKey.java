package uk.gov.hmcts.reform.security.keyvault;

import java.security.Key;

abstract class KeyVaultKey implements Key {

    // Vault Key or Secret Identifier
    private final String identifier;

    private final String algorithm;

    KeyVaultKey(String identifier, String algorithm) {
        this.identifier = identifier;
        this.algorithm = algorithm;
    }

    /**
     * @should return identifier
     */
    public String getIdentifier() {
        return identifier;
    }

    /**
     * @should return algorithm
     */
    // see JCA spec
    @Override
    public final String getAlgorithm() {
        return algorithm;
    }

    // see JCA spec
    @Override
    public final byte[] getEncoded() {
        byte[] encodedInternal = getEncodedInternal();
        return (encodedInternal == null) ? null : encodedInternal.clone();
    }

    abstract byte[] getEncodedInternal();
}
