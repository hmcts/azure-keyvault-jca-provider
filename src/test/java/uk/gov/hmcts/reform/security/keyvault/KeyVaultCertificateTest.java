package uk.gov.hmcts.reform.security.keyvault;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.security.cert.X509Certificate;
import java.util.Date;

import static org.mockito.Mockito.verify;

@RunWith(MockitoJUnitRunner.class)
public class KeyVaultCertificateTest {

    @Mock
    private X509Certificate certificate;

    @InjectMocks
    private KeyVaultCertificate vaultCertificate;

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#getEncoded()
     */
    @Test
    public void getEncoded_shouldCallDelegate() throws Exception {
        vaultCertificate.getEncoded();
        verify(certificate).getEncoded();
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#verify(java.security.PublicKey)
     */
    @Test
    public void verify_shouldCallDelegate() throws Exception {
        vaultCertificate.verify(null);
        verify(certificate).verify(null);
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#verify(java.security.PublicKey, String)
     */
    @Test
    public void verify_shouldCallDelegate2() throws Exception {
        vaultCertificate.verify(null, (String) null);
        verify(certificate).verify(null, (String) null);
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#checkValidity()
     */
    @Test
    public void checkValidity_shouldCallDelegate() throws Exception {
        vaultCertificate.checkValidity();
        verify(certificate).checkValidity();
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#checkValidity(java.util.Date)
     */
    @Test
    public void checkValidity_shouldCallDelegate2() throws Exception {
        Date date = new Date();
        vaultCertificate.checkValidity(date);
        verify(certificate).checkValidity(date);
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#getVersion()
     */
    @Test
    public void getVersion_shouldCallDelegate() {
        vaultCertificate.getVersion();
        verify(certificate).getVersion();
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#getSerialNumber()
     */
    @Test
    public void getSerialNumber_shouldCallDelegate() {
        vaultCertificate.getSerialNumber();
        verify(certificate).getSerialNumber();
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#getIssuerDN()
     */
    @Test
    public void getIssuerDN_shouldCallDelegate() {
        vaultCertificate.getIssuerDN();
        verify(certificate).getIssuerDN();
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#getSubjectDN()
     */
    @Test
    public void getSubjectDN_shouldCallDelegate() {
        vaultCertificate.getSubjectDN();
        verify(certificate).getSubjectDN();
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#getNotBefore()
     */
    @Test
    public void getNotBefore_shouldCallDelegate() {
        vaultCertificate.getNotBefore();
        verify(certificate).getNotBefore();
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#getNotAfter()
     */
    @Test
    public void getNotAfter_shouldCallDelegate() {
        vaultCertificate.getNotAfter();
        verify(certificate).getNotAfter();
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#getTBSCertificate()
     */
    @Test
    public void getTBSCertificate_shouldCallDelegate() throws Exception {
        vaultCertificate.getTBSCertificate();
        verify(certificate).getTBSCertificate();
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#getSignature()
     */
    @Test
    public void getSignature_shouldCallDelegate() {
        vaultCertificate.getSignature();
        verify(certificate).getSignature();
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#getSigAlgName()
     */
    @Test
    public void getSigAlgName_shouldCallDelegate() {
        vaultCertificate.getSigAlgName();
        verify(certificate).getSigAlgName();
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#getSigAlgOID()
     */
    @Test
    public void getSigAlgOID_shouldCallDelegate() {
        vaultCertificate.getSigAlgOID();
        verify(certificate).getSigAlgOID();
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#getSigAlgParams()
     */
    @Test
    public void getSigAlgParams_shouldCallDelegate() {
        vaultCertificate.getSigAlgParams();
        verify(certificate).getSigAlgParams();
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#getIssuerUniqueID()
     */
    @Test
    public void getIssuerUniqueID_shouldCallDelegate() {
        vaultCertificate.getIssuerUniqueID();
        verify(certificate).getIssuerUniqueID();
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#getSubjectUniqueID()
     */
    @Test
    public void getSubjectUniqueID_shouldCallDelegate() {
        vaultCertificate.getSubjectUniqueID();
        verify(certificate).getSubjectUniqueID();
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#getKeyUsage()
     */
    @Test
    public void getKeyUsage_shouldCallDelegate() {
        vaultCertificate.getKeyUsage();
        verify(certificate).getKeyUsage();
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#getBasicConstraints()
     */
    @Test
    public void getBasicConstraints_shouldCallDelegate() {
        vaultCertificate.getBasicConstraints();
        verify(certificate).getBasicConstraints();
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#hasUnsupportedCriticalExtension()
     */
    @Test
    public void hasUnsupportedCriticalExtension_shouldCallDelegate() {
        vaultCertificate.hasUnsupportedCriticalExtension();
        verify(certificate).hasUnsupportedCriticalExtension();
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#getCriticalExtensionOIDs()
     */
    @Test
    public void getCriticalExtensionOIDs_shouldCallDelegate() {
        vaultCertificate.getCriticalExtensionOIDs();
        verify(certificate).getCriticalExtensionOIDs();
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#getNonCriticalExtensionOIDs()
     */
    @Test
    public void getNonCriticalExtensionOIDs_shouldCallDelegate() {
        vaultCertificate.getNonCriticalExtensionOIDs();
        verify(certificate).getNonCriticalExtensionOIDs();
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#getExtensionValue(String)
     */
    @Test
    public void getExtensionValue_shouldCallDelegate() {
        vaultCertificate.getExtensionValue("oid");
        verify(certificate).getExtensionValue("oid");
    }

    /**
     * @verifies call delegate
     * @see KeyVaultCertificate#getPublicKey()
     */
    @Test
    public void getPublicKey_shouldCallDelegate() {
        vaultCertificate.getPublicKey();
        verify(certificate).getPublicKey();
    }
}
