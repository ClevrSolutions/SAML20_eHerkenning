package saml20.implementation.metadata;

import com.mendix.core.Core;
import com.mendix.core.CoreException;
import com.mendix.logging.ILogNode;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IMendixIdentifier;
import com.mendix.systemwideinterfaces.core.IMendixObject;
import org.apache.commons.lang.StringUtils;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.metadata.*;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.X509Support;
import org.opensaml.xmlsec.signature.X509Data;
import saml20.implementation.common.Constants;
import saml20.proxies.NameIDFormat;
import saml20.proxies.SSOConfiguration;
import saml20.proxies.TypeOfAuthnContext;

import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.*;

public class IdpMetadata extends IMetadata {
    private static IdpMetadata instance;
    private HashMap<String, String> AliasSet = new HashMap<String, String>();
    private HashMap<String, Metadata> metadataSet = new HashMap<String, Metadata>();
    private boolean initialized = false;

    private static ILogNode _logNode = Core.getLogger(Constants.LOGNODE);

    public IdpMetadata() throws SAMLException {
    }

    public static IdpMetadata getInstance() throws SAMLException {
        if (instance == null)
            instance = new IdpMetadata();

        return instance;
    }

    public IdpMetadata updateConfiguration(IContext context, List<IMendixObject> ssoConfigurationList) throws SAMLException {
        HashMap<String, Metadata> metadata = new HashMap<String, Metadata>();
        for (IMendixObject ssoConfiguration : ssoConfigurationList) {

            String entityAlias = ssoConfiguration.getValue(context, SSOConfiguration.MemberNames.Alias.toString());
            if (entityAlias == null || entityAlias.isEmpty())
                throw new SAMLException("No Alias Configured for this Configurations");

            else {
                EntityDescriptor ed = getIdpEntityDescriptor(context, ssoConfiguration);
                if (ed == null)
                    throw new SAMLException("No Entity Id Configured for this IdP(" + entityAlias + ")");

                Metadata md = new Metadata(ssoConfiguration, ed, Constants.PROTOCOL);
                metadata.put(md.getEntityID(), md);

                this.AliasSet.put(md.getAlias(context), md.getEntityID());
            }
        }
        this.metadataSet.clear();
        this.metadataSet.putAll(metadata);

        this.initialized = true;

        return this;
    }

    public Metadata getMetadata(String entityId) throws SAMLException {
        if (!this.initialized)
            throw new SAMLException("The IdP Metadata has not been initialized.");
        Metadata md = this.metadataSet.get(entityId);
        if (md == null) {
            if (this.AliasSet.containsKey(entityId))
                md = this.metadataSet.get(this.AliasSet.get(entityId));

            if (md == null)
                throw new SAMLException("No Metadata found with entity ID " + entityId);
        }

        return md;
    }

    public Endpoint getEndPoint(String issuer) throws SAMLException {
        Metadata metadata = getMetadata(issuer);
        if (metadata != null)
            return metadata.findLoginEndpoint(Constants.getBindingURIs());

        return null;
    }

    /**
     * Fallback action to retrieve the first Metadata record, should only be used in case there is only IdP record configured.
     *
     * @return
     * @throws SAMLException
     */
    public Metadata getFirstMetadata() throws SAMLException {
        if (!this.initialized)
            throw new SAMLException("The IdP Metadata has not been initialized.");

        if (this.metadataSet.size() > 1)
            _logNode.info("GetFirstMetadata executed eventhough we have multiple IdPs specified. Please review your configuration.");

        return this.getMetadata(this.metadataSet.keySet().iterator().next());
    }

    public Collection<Metadata> getAllMetaData() {
        return this.metadataSet.values();
    }

    /**
     * Find the First IdP Metadata record that matches any of the specified EntityId Aliases
     *
     * @param entityId
     * @return Metadata
     */
    public Metadata findSupportedEntity(String entityId) {
        if (this.metadataSet.containsKey(entityId)) {
            return this.metadataSet.get(entityId);
        }

        if (this.AliasSet.containsKey(entityId)) {
            if (this.metadataSet.containsKey(this.AliasSet.get(entityId))) {
                return this.metadataSet.get(this.AliasSet.get(entityId));
            }
        }

        _logNode.debug("No supported Entity Ids found in set: " + entityId + " supported ids: " + this.metadataSet.keySet() + ", aliases: " + this.AliasSet.keySet());

        return null;
    }

    public static EntityDescriptor getIdpEntityDescriptor(IContext context, IMendixObject ssoConfiguration) throws SAMLException {
        String preferredEntityId = "{unknown}";
        try {
            IMendixIdentifier idpMetaDataId = ssoConfiguration.getValue(context, SSOConfiguration.MemberNames.SSOConfiguration_IdPMetadata.toString());
            if (idpMetaDataId == null)
                throw new RuntimeException("No IdP Metadata file located");

            IMendixIdentifier entityDescriptorId = ssoConfiguration.getValue(context, SSOConfiguration.MemberNames.SSOConfiguration_PreferedEntityDescriptor.toString());
            if (entityDescriptorId == null)
                throw new RuntimeException("No entity descriptor was selected for the SSO Configuration");

            IMendixObject mxEntityDescriptor = Core.retrieveId(context, entityDescriptorId);
            preferredEntityId = (String) mxEntityDescriptor.getValue(context, saml20.proxies.EntityDescriptor.MemberNames.entityID.toString());


            IMendixObject IdPMetadataObject = Core.retrieveId(context, idpMetaDataId);
            List<EntityDescriptor> list;
            try (InputStream inputStream = Core.getFileDocumentContent(context, IdPMetadataObject)) {
                list = getListOfIdpMetadata(inputStream);
            }
            for (EntityDescriptor ed : list) {
                if (preferredEntityId.equals(ed.getEntityID()))
                    return ed;
            }
        } catch (CoreException | RuntimeException | IOException e) {
            _logNode.error("Unable to load the IdP Metadata", e);
        }

        throw new SAMLException("Unable to find an Entity Descriptor with id: " + preferredEntityId);
    }

    public static class Metadata {
        private EntityDescriptor entityDescriptor;
        private IDPSSODescriptor idpSSODescriptor;
        private IMendixObject ssoConfiguration;
        private Collection<X509Certificate> validCertificates = new HashSet<X509Certificate>();
        private Collection<X509Certificate> signingCertificates = new HashSet<X509Certificate>();

        private AuthnContextComparisonTypeEnumeration authnContext = null;
        private String nameIDFormat = null;
        private Boolean diableNameIDPolicy = null;

        private Metadata(IMendixObject ssoConfiguration, EntityDescriptor entityDescriptor, String protocol) throws SAMLException {
            this.entityDescriptor = entityDescriptor;
            this.ssoConfiguration = ssoConfiguration;
            this.idpSSODescriptor = entityDescriptor.getIDPSSODescriptor(protocol);

            for (KeyDescriptor keyDescriptor : this.idpSSODescriptor.getKeyDescriptors()) {
                UsageType usage = keyDescriptor.getUse();
                for (X509Data x509Data : keyDescriptor.getKeyInfo().getX509Datas()) {
                    List<org.opensaml.xmlsec.signature.X509Certificate> certList = x509Data.getX509Certificates();
                    for (org.opensaml.xmlsec.signature.X509Certificate certificate : certList) {
                        try {
                            final String value = certificate.getValue();
                            if(StringUtils.isBlank(value)){
                                _logNode.info("Certificate " + certificate + " is empty!");
                                continue;
                            }
                            X509Certificate cert = X509Support.decodeCertificate(value);
                            if (usage == UsageType.SIGNING)
                                this.signingCertificates.add(cert);
                            else
                                this.validCertificates.add(cert);
                        } catch (Exception e) {
                            throw new SAMLException("Error occured while building list of available certificates: " + e);
                        }
                    }
                }
            }

            if (this.signingCertificates.size() == 0 && this.validCertificates.size() == 0) {
                throw new IllegalStateException("IdP Metadata does not contain any certificate: " + getEntityID());
            }
        }

        public void addCertificates(Collection<X509Certificate> certificates) {
            this.validCertificates.addAll(certificates);
        }

        /**
         * @return The entityID of the Login Site
         */
        public String getEntityID() {
            return this.entityDescriptor.getEntityID();
        }

        public IMendixObject getSsoConfiguration() {
            return this.ssoConfiguration;
        }

        public String getAlias(IContext context) {
            return (String) this.ssoConfiguration.getValue(context, SSOConfiguration.MemberNames.Alias.toString());
        }

        /**
         * @return The location (URL) of {@link ArtifactResolutionService}.
         */
        public String getArtifactResolutionServiceLocation(String binding) throws IllegalArgumentException {
            for (ArtifactResolutionService artifactResolutionService : this.idpSSODescriptor.getArtifactResolutionServices()) {
                if (SAMLConstants.SAML2_SOAP11_BINDING_URI.equals(artifactResolutionService.getBinding())) {
                    return artifactResolutionService.getLocation();
                }
            }
            throw new IllegalArgumentException("No artifact resolution service for binding " + binding);
        }

        /**
         * Get a signon service location for a specific binding.
         *
         * @param binding SAML binding name,
         * @return The url for the location.
         * @throws IllegalArgumentException if the binding is not present in metadata.
         */
        public String getSingleSignonServiceLocation(String binding) throws IllegalArgumentException {
            for (SingleSignOnService service : this.idpSSODescriptor.getSingleSignOnServices()) {
                if (service.getBinding().equals(binding)) {
                    return service.getLocation();
                }
            }
            throw new IllegalArgumentException("Binding " + binding + " not found");
        }

        public String getAttributeQueryServiceLocation(String binding) throws IllegalArgumentException {
            AttributeAuthorityDescriptor descriptor = this.entityDescriptor.getAttributeAuthorityDescriptor(SAMLConstants.SAML20P_NS);
            if (descriptor == null)
                throw new IllegalArgumentException("Metadata does not contain a AttributeAuthorityDescriptor");
            for (AttributeService service : descriptor.getAttributeServices()) {
                if (binding.equals(service.getBinding())) {
                    return service.getLocation();
                }
            }
            throw new IllegalArgumentException("Binding " + binding + " not found in AttributeServices");
        }

        public List<SingleSignOnService> getSingleSignonServices() {
            return this.idpSSODescriptor.getSingleSignOnServices();
        }

        public List<SingleLogoutService> getSingleLogoutServices() {
            return this.idpSSODescriptor.getSingleLogoutServices();
        }

        /**
         * @return The response location (URL) of {@link SingleSignOnService} at the Login Site
         */
        public String getSingleLogoutServiceResponseLocation() {
            if (this.idpSSODescriptor.getSingleLogoutServices().size() > 0) {
                List<SingleLogoutService> singleLogoutServices = this.idpSSODescriptor.getSingleLogoutServices();

                // Prefer POST binding - due to browser redirect limitations.
                SingleLogoutService singleLogoutService = this.idpSSODescriptor.getSingleLogoutServices().get(0);
                for (SingleLogoutService sls : singleLogoutServices) {
                    if (sls.getBinding().equals(SAMLConstants.SAML2_POST_BINDING_URI)) {
                        singleLogoutService = sls;
                        break;
                    }
                }

                String location = singleLogoutService.getResponseLocation();
                if (location == null) {
                    location = singleLogoutService.getLocation();
                }
                return location;
            }
            return null;
        }

        Collection<X509Certificate> getAllCertificates() {
            return this.validCertificates;
        }

        /**
         * Get a list of all valid certificates for this IdP.
         * <p>
         * Any expired or revoked certificates will not be included in the list.
         */
        public Collection<X509Certificate> getCertificates() {
            Collection<X509Certificate> res = new ArrayList<X509Certificate>();
            for (X509Certificate certificate : this.validCertificates) {
                if (certificate.getNotAfter().after(new Date())) {
                    res.add(certificate);
                } else {
                    _logNode.debug("Local Metadata certificate for " + getEntityID() + " expired at " + certificate.getNotAfter() + ", current: " + new Date());
                }
            }
            return res;
        }

        /**
         * Get a list of all certificates marked as the signing certificate for this IdP.
         * <p>
         * Any expired or revoked certificates will not be included in the list.
         */
        public Collection<X509Certificate> getSigningCertificates() {
            Collection<X509Certificate> res = new ArrayList<X509Certificate>();
            for (X509Certificate certificate : this.signingCertificates) {
                if (certificate.getNotAfter().after(new Date())) {
                    res.add(certificate);
                } else {
                    _logNode.debug("Local Metadata certificate for " + getEntityID() + " expired at " + certificate.getNotAfter() + ", current: " + new Date());
                }
            }
            return res;
        }

        /**
         * Find a supported login endpoint.
         *
         * @throws IllegalArgumentException If no services match the selected bindings.
         */
        public Endpoint findLoginEndpoint(String[] bindings) {
            if (bindings == null)
                throw new IllegalArgumentException("bindings cannot be null");

            for (String binding : bindings) {
                for (SingleSignOnService service : this.idpSSODescriptor.getSingleSignOnServices()) {
                    if (service.getBinding().equalsIgnoreCase(binding)) {
                        return service;
                    }
                }
            }
            throw new IllegalArgumentException("No SingleSignOn Service found for " + Arrays.toString(bindings));
        }

        /**
         * Find a supported logout endpoint.
         *
         * @throws IllegalArgumentException If no services match the selected bindings.
         */
        public Endpoint findLogoutEndpoint(String[] bindings) {
            if (bindings == null)
                throw new IllegalArgumentException("bindings cannot be null");

            for (String binding : bindings) {
                for (SingleLogoutService service : this.idpSSODescriptor.getSingleLogoutServices()) {
                    if (service.getBinding().equalsIgnoreCase(binding)) {
                        return service;
                    }
                }
            }

            return null;
        }

        /**
         * Get the name format for an attribute.
         *
         * @param attribute     The attribute to look for.
         * @param defaultFormat The format to return if the attribute is not present in idp metadata.
         */
        public String getAttributeNameFormat(String attribute, String defaultFormat) {
            for (Attribute attr : this.idpSSODescriptor.getAttributes()) {
                if (attribute.equals(attr.getName())) {
                    return attr.getNameFormat();
                }
            }
            return defaultFormat;
        }

        public Collection<PublicKey> getPublicKeys() {
            Collection<PublicKey> res = new ArrayList<PublicKey>();
            for (X509Certificate cert : getCertificates()) {
                res.add(cert.getPublicKey());
            }
            return res;
        }

        public EntityDescriptor getEntityDescriptor() {
            return this.entityDescriptor;
        }

        public String nameIDFormatConfiguration(IContext context) {
            if (this.nameIDFormat == null) {
                IMendixIdentifier id = this.ssoConfiguration.getValue(context, SSOConfiguration.MemberNames.SSOConfiguration_NameIDFormat.toString());
                if (id != null) {
                    try {
                        IMendixObject nameId = Core.retrieveId(context, id);
                        this.nameIDFormat = (String) nameId.getValue(context, NameIDFormat.MemberNames.Description.toString());
                    } catch (Exception e) {
                        _logNode.warn("Unable to retreive name id format from database, falling back to transient.", e);
                        this.nameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
                    }
                } else
                    this.nameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
            }

            /*
             * Below is the possible list for all name id policies, just as a reference None of the SAML 1.1 policies
             * are supported because on all places in the code we assume that all requests are saml2.0
             */
            // urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified
            // urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
            // urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName
            // urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName

            // newNameIDPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos");
            // newNameIDPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
            // newNameIDPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
            // newNameIDPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");

            return this.nameIDFormat;
        }

        public AuthnContextComparisonTypeEnumeration typeOfAuthnContextConfiguration(IContext context) {
            if (this.authnContext != null)
                return this.authnContext;

            String value = this.ssoConfiguration.getValue(context, SSOConfiguration.MemberNames.AuthnContext.toString());
            if (value != null) {
                switch (TypeOfAuthnContext.valueOf(value)) {
                    case BETTER:
                        this.authnContext = AuthnContextComparisonTypeEnumeration.BETTER;
                        break;
                    case EXACT:
                        this.authnContext = AuthnContextComparisonTypeEnumeration.EXACT;
                        break;
                    case MAXIMUM:
                        this.authnContext = AuthnContextComparisonTypeEnumeration.MAXIMUM;
                        break;
                    case MINIMUM:
                        this.authnContext = AuthnContextComparisonTypeEnumeration.MINIMUM;
                        break;
                }
            }

            return this.authnContext;
        }

        public Boolean disableNameIDPolicyConfiguration(IContext context) {
            if (this.diableNameIDPolicy == null)
                this.diableNameIDPolicy = this.ssoConfiguration.getValue(context, SSOConfiguration.MemberNames.DisableNameIDPolicy.toString());

            return this.diableNameIDPolicy;
        }

    }

    public Collection<X509Certificate> getSigningCertificates(String entityId) throws SAMLException {
        Metadata metadata = this.getMetadata(entityId);
        if (metadata == null)
            return null;

        return metadata.getSigningCertificates();
    }

    public Collection<X509Certificate> getCertificates(String entityId) throws SAMLException {
        Metadata metadata = this.getMetadata(entityId);
        if (metadata == null)
            return null;

        return metadata.getCertificates();
    }
}
