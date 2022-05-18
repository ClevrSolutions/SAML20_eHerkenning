package saml20.implementation.wrapper;

import com.mendix.core.Core;
import com.mendix.logging.ILogNode;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.opensaml.core.xml.ElementExtensibleXMLObject;
import org.opensaml.core.xml.Namespace;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLMetadataContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.opensaml.xmlsec.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import saml20.implementation.SAMLRequestContext;
import saml20.implementation.common.Constants;
import saml20.implementation.common.SAMLUtil;
import saml20.implementation.metadata.IdpMetadata.Metadata;
import saml20.proxies.EncryptionMethod;

import javax.xml.crypto.dsig.XMLSignature;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Optional;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import static java.nio.charset.StandardCharsets.UTF_8;

public class MxSAMLObject {
    private static final ILogNode _logNode = Core.getLogger(Constants.LOGNODE);

    private final SAMLObject obj;

    public MxSAMLObject(SAMLObject obj) {
        if (obj == null)
            throw new IllegalArgumentException("Object cannot be null");

        this.obj = obj;
    }

    private static void initializeContextEntityInformation(MessageContext<SAMLObject> context, Endpoint destination, Metadata metadata) {
        // Endpoint and metadata is now set via subcontexts (see also: https://wiki.shibboleth.net/confluence/display/OS30/MessageContext+Subcontext+Usage%3A+SAML+1+and+SAML+2)
        SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);
        SAMLMetadataContext metadataContext = peerEntityContext.getSubcontext(SAMLMetadataContext.class, true);
        SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
        endpointContext.setEndpoint(destination);

        EntityDescriptor entity = metadata.getEntityDescriptor();

        RoleDescriptor role = entity.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
        peerEntityContext.setEntityId(entity.getEntityID());
        metadataContext.setEntityDescriptor(entity);
        metadataContext.setRoleDescriptor(role);
    }

    /**
     * Get an XML representation of the object.
     *
     * @throws SAMLException
     */
    public String toXML() throws SAMLException {
        Element e = SAMLUtil.marshallObject(this.obj);
        return SerializeSupport.prettyPrintXML(e);
    }

    /**
     * Encode the SAML object to a base64 encoded string.
     *
     * @return The XML representation encoded with base64.
     * @throws SAMLException
     */
    public String toBase64() throws SAMLException {
        Element element = SAMLUtil.marshallObject(this.obj);
        String xml = SerializeSupport.nodeToString(element);
        return Base64.getEncoder().encodeToString(xml.getBytes());
    }

    public boolean hasSignature() {
        if (!(this.obj instanceof SignableSAMLObject))
            return false;
        return ((SignableSAMLObject) this.obj).getSignature() != null;
    }

    /**
     * Check that a given object has been signed correctly with a specific {@link PublicKey}.
     *
     * @return true, if the signableObject has been signed correctly with the given key. Returns <code>false</code> if
     * the object is not signed at all.
     */
    public boolean verifySignature(X509Certificate certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate cannot be null");
        }
        Signature signature = null;
        if (this.obj instanceof SignableSAMLObject) {
            SignableSAMLObject signableObject = (SignableSAMLObject) this.obj;
            _logNode.debug("Signable object is signed: " + signableObject.isSigned());
            signature = signableObject.getSignature();
            signature.setParent(signableObject);
            try {
                // profile validation needs cached DOM object
                signableObject.setDOM(XMLObjectSupport.marshall(signableObject));
            } catch (MarshallingException e) {
                throw new RuntimeException("Couldn't marshall signable object", e);
            }
        } else if (this.obj instanceof ElementExtensibleXMLObject) {
            signature = SAMLUtil.getFirstElement((ElementExtensibleXMLObject) this.obj, Signature.class);
        }

        if (signature == null) {
            _logNode.warn("No signature present in object " + this.obj);
            return false;
        }

        // verify signature element according to SAML profile
        SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
        try {
            _logNode.debug("Signature DOM: " + SerializeSupport.prettyPrintXML(signature.getDOM()));
            profileValidator.validate(signature);
        } catch (Exception e) {
            _logNode.warn("The signature does not meet the requirements indicated by the SAML profile of the XML signature", e);
            return false;
        }

        // verify signature
        BasicX509Credential credential = new BasicX509Credential(certificate);
        try {
            final Key certificateKey = CredentialSupport.extractVerificationKey(credential);
            _logNode.debug("Extracted public key from credential: " + certificateKey);
//            LOGGER.debug("Keys: " + String.join(",", signature.getSigningCredential().getKeyNames()));
//            final sun.security.rsa.RSAPublicKeyImpl signatureKey = (RSAPublicKeyImpl) signature.getSigningCredential().getPublicKey();
//            LOGGER.debug("Extracted public key from signature: " + signatureKey);
            SignatureValidator.validate(signature, credential);
            return true;
        } catch (SignatureException e) {
            // BJHL 2016-02-18 Moved from warning to trace. Another certificate might match, verification failure should be handled by caller of this method.
            _logNode.trace("The signature does not match the signature of the login site", e);

            // FIXME: skipped signature validation for now
            return false;
        }
    }

    /**
     * Sign the saml object.
     * <p>
     * The effect of calling this method is that a new Signature element is created, and the object is marshalled. If
     * {@link #toXML()} is called, the XML will contain a valid signature.
     *
     * @param signingCredential The credential used for signing the object.
     * @throws SAMLException
     */
    public void sign(Credential signingCredential, String encryptionMethod) throws SAMLException {
        Signature signature = SAMLUtil.buildXMLObject(Signature.class);
        if (!(this.obj instanceof SignableSAMLObject)) {
            throw new IllegalStateException("Object of type " + this.obj.getClass() + " is not signable");
        }
        // manually add the ds namespace, as it will be added to the inclusiveNamespaces element
        this.obj.getNamespaceManager().registerNamespaceDeclaration(new Namespace(XMLSignature.XMLNS, "ds"));
        final SignatureSigningConfiguration securityConfig = SecurityConfigurationSupport.getGlobalSignatureSigningConfiguration();

        signature.setSigningCredential(signingCredential);
        if (encryptionMethod.equals(EncryptionMethod.SHA256WithRSA.toString())) {
            signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        } else {
            signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        }

        // FIXME: verify that this is correct
        signature.setCanonicalizationAlgorithm(securityConfig.getSignatureCanonicalizationAlgorithm());
        _logNode.debug("HMAC output length: " + securityConfig.getSignatureHMACOutputLength());
        signature.setHMACOutputLength(securityConfig.getSignatureHMACOutputLength());

        // JPU - 20200720 - Should no longer be needed in OpenSAML 3.0
//        try {
//            SecurityHelper.prepareSignatureParams(signature, signingCredential, null, null);
//        } catch (SecurityException e) {
//            throw new SAMLException(e);
//        }

        final Optional<KeyInfo> keyInfo = Optional.ofNullable(securityConfig.getKeyInfoGeneratorManager())
                .flatMap(namedKeyInfoGeneratorManager -> Optional.ofNullable(namedKeyInfoGeneratorManager.getDefaultManager().getFactory(signingCredential)))
                .map(KeyInfoGeneratorFactory::newInstance)
                .map(keyInfoGenerator -> {
                    try {
                        return keyInfoGenerator.generate(signingCredential);
                    } catch (SecurityException e) {
                        throw new RuntimeException("Couldn't generate key info", e);
                    }
                });

        if (keyInfo.isPresent()) {
            signature.setKeyInfo(keyInfo.get());
        } else {
            _logNode.warn("No KeyInfo will be generated for Signature");
        }

        ((SignableSAMLObject) this.obj).setSignature(signature);

        try {
            Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(this.obj);
            if (marshaller == null) {
                throw new RuntimeException("No marshaller registered for " + this.obj.getElementQName() + ", unable to marshall in preperation for signing");
            }
            marshaller.marshall(this.obj);
            Signer.signObject(signature);
        } catch (MarshallingException e) {
            _logNode.error("Unable to marshall protocol message in preparation for signing", e);
            throw new SAMLException(e);
        } catch (SignatureException e) {
            _logNode.error("Unable to sign protocol message", e);
            throw new SAMLException(e);
        }
    }

    public String getRedirectURL(SAMLRequestContext requestContext, Metadata metadata, Endpoint destination, String relayState) throws SAMLException {
        Encoder enc = new Encoder();
        try {
            return enc.buildRedirectURL(requestContext, metadata, relayState, destination);
        } catch (MessageEncodingException e) {
            throw new SAMLException(e);
        }
    }

    public MessageContext<SAMLObject> buildMessageContext(MxSAMLObject mxSAMLObject, SAMLRequestContext requestContext, Metadata metadata, Endpoint destination, String relayState, boolean useEncryption) throws SAMLException {

        MessageContext<SAMLObject> messageContext = new MessageContext<SAMLObject>();
        // Build the parameters for the request
        messageContext.setMessage(mxSAMLObject.obj);
        // RelayState is now set via this helper method, or it can be performed via:
        // messageContext.getSubcontext(SAMLBindingContext.class, true).setRelayState(uuid);
        SAMLBindingSupport.setRelayState(messageContext, relayState);

        // Sign the parameters
        final Credential credential = requestContext.getCredential();
        String encryptionMethod = requestContext.getSpMetadata().getEncryptionAlgorithm(requestContext.getIContext());
        if (useEncryption) {
            mxSAMLObject.sign(credential, encryptionMethod);
        }

        // Set the message
        messageContext.setMessage(mxSAMLObject.obj);
        // No response adapters needed anymore; the response now gets set directly on the encoder
        // MessageContext and HttpServletResponse now get set directly on the encoder

        initializeContextEntityInformation(messageContext, destination, metadata);

        return messageContext;
    }

    protected class Encoder extends HTTPRedirectDeflateEncoder {
        public String buildRedirectURL(SAMLRequestContext requestContext, Metadata metadata, String relayState, Endpoint destination) throws MessageEncodingException, SAMLException {
            MessageContext<SAMLObject> messageContext = buildMessageContext(MxSAMLObject.this, requestContext, metadata, destination, relayState, true);


            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            String encoded;
            try (ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
                 DeflaterOutputStream deflaterStream = new DeflaterOutputStream(bytesOut, deflater)) {
                String messageStr = SerializeSupport.nodeToString(marshallMessage(MxSAMLObject.this.obj));
                deflaterStream.write(messageStr.getBytes(UTF_8));
                deflaterStream.finish();

                encoded = Base64.getEncoder().encodeToString(bytesOut.toByteArray());
            } catch (IOException e) {
                throw new RuntimeException("Unable to deflate message", e);
            }
            return super.buildRedirectURL(messageContext, destination.getLocation(), encoded);
        }
    }

}
