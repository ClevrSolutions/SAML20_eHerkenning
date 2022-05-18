package saml20.implementation.security;

import com.mendix.core.Core;
import com.mendix.logging.ILogNode;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IMendixIdentifier;
import com.mendix.systemwideinterfaces.core.IMendixObject;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;
import org.apache.xml.security.algorithms.JCEMapper;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.security.x509.BasicX509Credential;
import saml20.implementation.common.Constants;
import saml20.implementation.metadata.IdpMetadata.Metadata;
import saml20.proxies.EncryptionKeyLength;
import saml20.proxies.EncryptionMethod;
import saml20.proxies.SPMetadata;
import system.proxies.FileDocument;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;

/**
 * Some utility methods for building and loading certificates and the KeyStore
 */
public class SecurityHelper {

    private static ILogNode _logNode = Core.getLogger(Constants.LOGNODE);

    /**
     * Randomly generates a Java JCE KeyPair object from the specified XML Encryption algorithm URI.
     *
     * @param algoURI   The XML Encryption algorithm URI
     * @param keyLength the length of key to generate
     * @return a randomly-generated KeyPair
     * @throws NoSuchProviderException  provider not found
     * @throws NoSuchAlgorithmException algorithm not found
     */
    private static KeyPair generateKeyPairFromURI(String algoURI, int keyLength) throws NoSuchAlgorithmException, NoSuchProviderException {
        String jceAlgorithmName = JCEMapper.getJCEKeyAlgorithmFromURI(algoURI);
        return generateKeyPair(jceAlgorithmName, keyLength, null);
    }

    /**
     * Generate a random asymmetric key pair.
     *
     * @param algo      key algorithm
     * @param keyLength key length
     * @param provider  JCA provider
     * @return randomly generated key
     * @throws NoSuchAlgorithmException algorithm not found
     * @throws NoSuchProviderException  provider not found
     */
    private static KeyPair generateKeyPair(String algo, int keyLength, String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPair keyPair = null;
        KeyPairGenerator keyGenerator = null;
        if (provider != null) {
            keyGenerator = KeyPairGenerator.getInstance(algo, provider);
        } else {
            keyGenerator = KeyPairGenerator.getInstance(algo);
        }
        keyGenerator.initialize(keyLength);
        keyPair = keyGenerator.generateKeyPair();
        return keyPair;
    }

    private static X509Certificate generateCertificate(EncryptionMethod encrMethod, KeyPair keyPair, String entityId) throws Exception {
        X500Name issuer = new X500Name("cn=" + entityId + ", ou=Mendix-SP");
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60L * 60L * 24L); // Change the date to yesterday
        // to prevent any accidental
        // timezone issues
        Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60L * 60L * 24L * 365L * 10L);
        X500Name subject = new X500Name("cn=" + entityId + ", ou=Mendix-SP");

        @SuppressWarnings("resource")
        SubjectPublicKeyInfo publicKeyInfo;
        try (ByteArrayInputStream bIn = new ByteArrayInputStream(keyPair.getPublic().getEncoded());
             ASN1InputStream sequence = new ASN1InputStream(bIn)) {
            publicKeyInfo = new SubjectPublicKeyInfo((ASN1Sequence) sequence.readObject());
        }

        X509v3CertificateBuilder gen = new X509v3CertificateBuilder(issuer, serialNumber, notBefore, notAfter, subject, publicKeyInfo);

        gen.addExtension(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic()));
        gen.addExtension(Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(keyPair.getPublic()));

        ContentSigner sigGen = new JcaContentSignerBuilder((encrMethod != null ? encrMethod.toString() : EncryptionMethod.SHA1withRSA.toString()))
                .setProvider("BC").build(keyPair.getPrivate());
        X509CertificateHolder certificateHolder = gen.build(sigGen);

        X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
        return x509Certificate;
    }

    private static KeyStore getKeystore(InputStream input, EncryptionKeyLength encryptionKeyLength) throws SAMLException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        KeyStore keystore = null;
        input = new BufferedInputStream(input);

        int length = (encryptionKeyLength == EncryptionKeyLength._2048bit_Encryption ? 2048 : 1024);
        input.mark(length * length);

        try {
            keystore = loadStore(input, Constants.CERTIFICATE_PASSWORD, "PKCS12");
        } catch (IOException e) {
            _logNode.debug("Keystore is not of type 'PCKS12' Trying type 'JKS'. (" + e.getMessage() + ")");
            input.reset();
            keystore = loadStore(input, Constants.CERTIFICATE_PASSWORD, "JKS");
        }

        return keystore;
    }

    private static KeyStore loadStore(InputStream input, String password, String type) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        KeyStore ks = KeyStore.getInstance(type);
        char[] jksPassword = password.toCharArray();
        ks.load(input, jksPassword);
        input.close();
        return ks;
    }

    protected static KeyStore prepareKeystore(IContext context, IMendixObject spMetadataConfiguration, EncryptionMethod encryptionMethod, EncryptionKeyLength encryptionKeyLength, boolean createNewKeystore) {
        String entityId = spMetadataConfiguration.getValue(context, SPMetadata.MemberNames.EntityID.toString());

        File keystoreFile = new File(Constants.CERTIFICATE_LOCATION);
        if (keystoreFile.exists())
            keystoreFile.delete();

        IMendixIdentifier keyStoreId = spMetadataConfiguration.getValue(context, SPMetadata.MemberNames.SPMetadata_KeyStore.toString());
        IMendixObject keyStoreObj = null;

        try {
            try {
                if (keyStoreId != null) {
                    keyStoreObj = Core.retrieveId(context, keyStoreId);
                    if (!createNewKeystore
                            && (boolean) keyStoreObj.getValue(context, FileDocument.MemberNames.HasContents.toString())
                            && !(boolean) keyStoreObj.getValue(context, saml20.proxies.KeyStore.MemberNames.RebuildKeyStore.toString())) {

                        KeyStore ks;
                        try (InputStream inStr = Core.getFileDocumentContent(context, keyStoreObj);
                             FileOutputStream ous = new FileOutputStream(keystoreFile)) {

                            ks = getKeystore(inStr, encryptionKeyLength);
                            IOUtils.copy(Core.getFileDocumentContent(context, keyStoreObj), ous);
                            ous.flush();
                        }

                        String alias = (String) keyStoreObj.getValue(context, saml20.proxies.KeyStore.MemberNames.Alias.toString());

                        // (JPU) added April 16 2015 to fix bug, certificate not updated in sp_metadata.xml when
                        // uploading own key store file + setting credential values to include key store private and
                        // public key.
                        X509Certificate ksCert = (X509Certificate) ks.getCertificate(alias);

                        // FIXME: should we use the keystore adapter here?
//                        KeyStoreX509CredentialAdapter cred = new KeyStoreX509CredentialAdapter(ks, alias, Constants.CERTIFICATE_PASSWORD.toCharArray());

                        BasicX509Credential cred = new BasicX509Credential(ksCert);
                        if (ksCert == null) {
                            throw new SAMLException("Unable to load the certificate from the key store. If you have just added your own key store make sure the alias is equal to the entity ID of the SP (currently: " + alias + ") and add your key store again.");
                        } else {
                            try {
                                cred.setPrivateKey((PrivateKey) ks.getKey(alias, Constants.CERTIFICATE_PASSWORD.toCharArray()));
                            } catch (Exception e) {
                                throw new SAMLException("Unable to load the private key from the key store. If you have just added your own key store make sure the key store password is equal to the password configured in the model and add your key store again.");
                            }
                            cred.setEntityCertificate(ksCert);
//                            cred.setPublicKey(ksCert.getPublicKey()); // FIXME: this is not allowed on an X509 credential
                            CredentialRepository.getInstance().updateCredential(Constants.CERTIFICATE_PASSWORD, entityId, cred);
                        }

                        return ks;
                    }
                }
            } catch (SAMLException e) {
                throw new RuntimeException(e.getMessage(), e);
            } catch (Exception e) {
                _logNode.error("Unable to read the KeyStore from the configuration, creating new KeyStore", e);
            }

            int length = (encryptionKeyLength == EncryptionKeyLength._2048bit_Encryption ? 2048 : 1024);
            String alias = spMetadataConfiguration.getValue(context, SPMetadata.MemberNames.EntityID.toString());
            if (alias.isEmpty())
                alias = "Mendix-SAML";

            KeyPair kp = SecurityHelper.generateKeyPairFromURI("http://www.w3.org/2001/04/xmlenc#rsa-1_5", length);


            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(null, null);

            X509Certificate cert = SecurityHelper.generateCertificate(encryptionMethod, kp,
                    (String) spMetadataConfiguration.getValue(context, SPMetadata.MemberNames.EntityID.toString()));

            BasicX509Credential cred = new BasicX509Credential(cert, kp.getPrivate());

            // (JPU) added March 18 2015 to fix bug, certificate not updated in sp_metadata.xml when changing
            // certificate encryption methods.
            CredentialRepository.getInstance().updateCredential(Constants.CERTIFICATE_PASSWORD, alias, cred);

            ks.setKeyEntry(entityId, cred.getPrivateKey(), Constants.CERTIFICATE_PASSWORD.toCharArray(), new Certificate[]{cert});

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ks.store(bos, Constants.CERTIFICATE_PASSWORD.toCharArray());

            bos.writeTo(new FileOutputStream(Constants.CERTIFICATE_LOCATION));
            bos.flush();
            bos.close();

            FileInputStream fis = new FileInputStream(Constants.CERTIFICATE_LOCATION);
            if (keyStoreObj == null) {
                keyStoreObj = Core.instantiate(context, saml20.proxies.KeyStore.entityName);
                keyStoreObj.setValue(context, FileDocument.MemberNames.Name.toString(), "SPMetaData.jks");
                keyStoreObj.setValue(context, saml20.proxies.KeyStore.MemberNames.SPMetadata_KeyStore.toString(), spMetadataConfiguration.getId());
            }
            keyStoreObj.setValue(context, saml20.proxies.KeyStore.MemberNames.LastChangedOn.toString(), new Date());
            keyStoreObj.setValue(context, saml20.proxies.KeyStore.MemberNames.Alias.toString(), alias);
            Core.storeFileDocumentContent(context, keyStoreObj, fis);

            return ks;
        } catch (Exception e) {
            _logNode.error("Unable to generate credential", e);
            throw new RuntimeException("Unable to generate credential", e);
        }
    }

    public static KeyStore appendToIdPKeyStore(KeyStore ks, Metadata idpMetadata) throws SAMLException {
        try {
            if (ks == null) {
                ks = KeyStore.getInstance("JKS");
                ks.load(null, null);
            }

            String conflictingCertificates = addAllToKeyStore(ks, idpMetadata.getCertificates());
            conflictingCertificates += addAllToKeyStore(ks, idpMetadata.getSigningCertificates());

            if (!"".equals(conflictingCertificates))
                throw new SAMLException("Unable to load the IdP Keystore, the following certificates are conflicting for Idp: " + idpMetadata.getEntityID() + " - " + conflictingCertificates);
        } catch (IOException | NoSuchAlgorithmException | KeyStoreException | CertificateException e) {
            throw new SAMLException(e);
        }

        return ks;
    }

    /**
     * Returns string of certificates that were conflicting
     */
    private static String addAllToKeyStore(KeyStore ks, Collection<X509Certificate> certificates)
            throws CertificateEncodingException, KeyStoreException {
        String conflictingCertificates = "";
        for (X509Certificate cert : certificates) {
            // thumbprint, see https://stackoverflow.com/questions/1270703/how-to-retrieve-compute-an-x509-certificates-thumbprint-in-java
            String alias = DigestUtils.sha1Hex(cert.getEncoded()) + "|" + cert.getVersion() + "|" + cert.getSerialNumber();
            String friendlyName = cert.getSubjectDN().getName() + "::" + cert.getIssuerDN().getName();

            if (ks.containsAlias(alias)) {
                if (!ks.getCertificate(alias).equals(cert)) {
                    conflictingCertificates += friendlyName + "|";
                } else {
                    _logNode.warn("The following certificate is being used twice: " + friendlyName);
                }
            }
            ks.setCertificateEntry(alias, cert);
        }
        return conflictingCertificates;
    }
}
