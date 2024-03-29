package uk.gov.hmcts.reform.security.keyvault;

import com.azure.security.keyvault.keys.cryptography.models.SignResult;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SignatureSpi;
import java.util.HashMap;
import java.util.Map;

public abstract class KeyVaultRSASignature extends SignatureSpi {

    private String identifier;

    private byte[] data;

    private final MessageDigest messageDigest;

    private final KeyVaultService vaultService;

    private static final Map<PrivateKey, String> KEY_IDENTIFIER_MAP = new HashMap<>();

    KeyVaultRSASignature(String algorithm) {
        this(algorithm, KeyVaultService.getInstance());
    }

    KeyVaultRSASignature(String algorithm, KeyVaultService vaultService) {
        this.vaultService = vaultService;
        try {
            messageDigest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new ProviderException(e);
        }
    }

    /**
     * @should throw exception
     */
    @Override
    protected void engineInitVerify(PublicKey publicKey) {
        throw new UnsupportedOperationException();
    }

    /**
     * @should set identifier if param is valid
     * @should throw exception if param is not valid
     */
    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof KeyVaultRSAPrivateKey)) {
            throw new InvalidKeyException("PrivateKey must be an instance of " + KeyVaultRSAPrivateKey.class.getName());
        }
        if (!KEY_IDENTIFIER_MAP.containsKey(privateKey)) {
            System.out.println("KEY IDENTIFIER NOT FOUND, ADDING TO MAP. KEY IDENTIFIER : " + privateKey);
            KEY_IDENTIFIER_MAP.put(privateKey, clearVersionFromKey(((KeyVaultKey) privateKey).getIdentifier()));
        }
        identifier = KEY_IDENTIFIER_MAP.get(privateKey);
    }

    protected String clearVersionFromKey(String keyId) {
        if (keyId != null && keyId.length() > 0) {
            try {
                URL url = new URL(keyId);
                String[] tokens = url.getPath().split("/");
                String version = (tokens.length >= 4 ? tokens[3] : "");
                return keyId.replace(version, "");
            } catch (MalformedURLException e) {
                System.out.println("Malformed URL Key Identifier : " + keyId);
            }
        }
        return keyId;
    }

    /**
     * @should throw exception
     */
    @Override
    protected void engineUpdate(byte byt) {
        throw new UnsupportedOperationException();
    }

    /**
     * @should throw exception if offset is not zero
     */
    @Override
    protected void engineUpdate(byte[] bytes, int off, int len) {
        if (off != 0) {
            throw new UnsupportedOperationException();
        }

        data = new byte[len];
        System.arraycopy(bytes, off, data, off, len - off);
    }

    /**
     * @should sign data
     */
    @Override
    protected byte[] engineSign() {
        /*
        Sign and Verify: Strictly, this operation is "sign hash" or “verify hash” as Azure Key Vault
        does not support hashing of content as part of signature creation.
        Applications should hash data to be signed locally and then request Azure Key Vault sign the hash
         */
        byte[] digest = messageDigest.digest(data);
        messageDigest.reset();
        SignResult result = vaultService.sign(identifier, SignatureAlgorithm.RS256, digest);
        return result.getSignature();
    }

    /**
     * @should throw exception
     */
    @Override
    protected boolean engineVerify(byte[] sigBytes) {
        throw new UnsupportedOperationException();
    }

    /**
     * @should throw exception
     */
    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new UnsupportedOperationException();
    }

    /**
     * @should throw exception
     */
    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new UnsupportedOperationException();
    }

    // Nested class for MD2withRSA signatures
    public static final class MD2withRSA extends KeyVaultRSASignature {
        public MD2withRSA() {
            super("MD2");
        }

        MD2withRSA(KeyVaultService vaultService) {
            super("MD2", vaultService);
        }
    }

    // Nested class for MD5withRSA signatures
    public static final class MD5withRSA extends KeyVaultRSASignature {
        public MD5withRSA() {
            super("MD5");
        }

        MD5withRSA(KeyVaultService vaultService) {
            super("MD5", vaultService);
        }
    }

    // Nested class for SHA1withRSA signatures
    public static final class SHA1withRSA extends KeyVaultRSASignature {
        public SHA1withRSA() {
            super("SHA-1");
        }

        SHA1withRSA(KeyVaultService vaultService) {
            super("SHA-1", vaultService);
        }
    }

    // Nested class for SHA224withRSA signatures
    public static final class SHA224withRSA extends KeyVaultRSASignature {
        public SHA224withRSA() {
            super("SHA-224");
        }

        SHA224withRSA(KeyVaultService vaultService) {
            super("SHA-224", vaultService);
        }
    }

    // Nested class for SHA256withRSA signatures
    public static final class SHA256withRSA extends KeyVaultRSASignature {
        public SHA256withRSA() {
            super("SHA-256");
        }

        SHA256withRSA(KeyVaultService vaultService) {
            super("SHA-256", vaultService);
        }
    }

    // Nested class for SHA384withRSA signatures
    public static final class SHA384withRSA extends KeyVaultRSASignature {
        public SHA384withRSA() {
            super("SHA-384");
        }

        SHA384withRSA(KeyVaultService vaultService) {
            super("SHA-384", vaultService);
        }
    }

    // Nested class for SHA512withRSA signatures
    public static final class SHA512withRSA extends KeyVaultRSASignature {
        public SHA512withRSA() {
            super("SHA-512");
        }

        SHA512withRSA(KeyVaultService vaultService) {
            super("SHA-512", vaultService);
        }
    }
}
