package uk.gov.hmcts.reform.security.keyvault;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

final class KeyVaultCertificate extends X509Certificate {

    private final X509Certificate certificate;

    KeyVaultCertificate(X509Certificate certificate) {
        super();

        this.certificate = certificate;
    }

    /**
     * @should call delegate
     */
    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        return certificate.getEncoded();
    }

    /**
     * @should call delegate
     */
    @Override
    public void verify(PublicKey key) throws NoSuchProviderException, CertificateException, NoSuchAlgorithmException,
        InvalidKeyException, SignatureException {
        certificate.verify(key);
    }

    /**
     * @should call delegate
     */
    @Override
    public void verify(PublicKey key, String sigProvider) throws NoSuchProviderException, CertificateException,
        NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        certificate.verify(key, sigProvider);
    }

    /**
     * @should call delegate
     */
    @Override
    public PublicKey getPublicKey() {
        return certificate.getPublicKey();
    }

    @Override
    public String toString() {
        return certificate.toString();
    }

    /**
     * @should call delegate
     */
    @Override
    public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
        certificate.checkValidity();
    }

    /**
     * @should call delegate
     */
    @Override
    public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        certificate.checkValidity(date);
    }

    /**
     * @should call delegate
     */
    @Override
    public int getVersion() {
        return certificate.getVersion();
    }

    /**
     * @should call delegate
     */
    @Override
    public BigInteger getSerialNumber() {
        return certificate.getSerialNumber();
    }

    /**
     * @should call delegate
     */
    @Override
    public Principal getIssuerDN() {
        return certificate.getIssuerDN();
    }

    /**
     * @should call delegate
     */
    @Override
    public Principal getSubjectDN() {
        return certificate.getSubjectDN();
    }

    /**
     * @should call delegate
     */
    @Override
    public Date getNotBefore() {
        return certificate.getNotBefore();
    }

    /**
     * @should call delegate
     */
    @Override
    public Date getNotAfter() {
        return certificate.getNotAfter();
    }

    /**
     * @should call delegate
     */
    @Override
    public byte[] getTBSCertificate() throws CertificateEncodingException {
        return certificate.getTBSCertificate();
    }

    /**
     * @should call delegate
     */
    @Override
    public byte[] getSignature() {
        return certificate.getSignature();
    }

    /**
     * @should call delegate
     */
    @Override
    public String getSigAlgName() {
        return certificate.getSigAlgName();
    }

    /**
     * @should call delegate
     */
    @Override
    public String getSigAlgOID() {
        return certificate.getSigAlgOID();
    }

    /**
     * @should call delegate
     */
    @Override
    public byte[] getSigAlgParams() {
        return certificate.getSigAlgParams();
    }

    /**
     * @should call delegate
     */
    @Override
    public boolean[] getIssuerUniqueID() {
        return certificate.getIssuerUniqueID();
    }

    /**
     * @should call delegate
     */
    @Override
    public boolean[] getSubjectUniqueID() {
        return certificate.getSubjectUniqueID();
    }

    /**
     * @should return null
     */
    @Override
    public boolean[] getKeyUsage() {
        // Remove Extended Key Usages (EKUs) flags as ForgeRock 7.x is now checking them and might
        // refuse to use a certificate if it hasn't been properly configured in KeyVault.
        // NO EKUs is equivalent to disabling the checks in AM.
        return null;
    }

    /**
     * @should call delegate
     */
    @Override
    public int getBasicConstraints() {
        return certificate.getBasicConstraints();
    }

    /**
     * @should call delegate
     */
    @Override
    public boolean hasUnsupportedCriticalExtension() {
        return certificate.hasUnsupportedCriticalExtension();
    }

    /**
     * @should call delegate
     */
    @Override
    public Set<String> getCriticalExtensionOIDs() {
        return certificate.getCriticalExtensionOIDs();
    }

    /**
     * @should call delegate
     */
    @Override
    public Set<String> getNonCriticalExtensionOIDs() {
        return certificate.getNonCriticalExtensionOIDs();
    }

    /**
     * @should call delegate
     */
    @Override
    public byte[] getExtensionValue(String oid) {
        return certificate.getExtensionValue(oid);
    }
}
