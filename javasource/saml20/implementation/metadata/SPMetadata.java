package saml20.implementation.metadata;

import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IMendixObject;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.*;
import saml20.implementation.common.Constants;
import saml20.implementation.security.CredentialRepository;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

public class SPMetadata extends IMetadata {

    private boolean initialized = false;
    private EntityDescriptor entityDescriptor;
    private SPSSODescriptor spSSODescriptor;
    private IMendixObject spMetadataObject;
    private static SPMetadata instance;

    private SPMetadata() {
    }

    public SPMetadata updateConfiguration(IContext context, IMendixObject spMetadata, CredentialRepository credentialRepository) throws SAMLException {
        try (ByteArrayOutputStream out = SPMetadataGenerator.generate(context, spMetadata, credentialRepository);
             InputStream inputStream = new ByteArrayInputStream(out.toByteArray())) {

            String preferredEntityId = spMetadata.getValue(context, saml20.proxies.SPMetadata.MemberNames.EntityID.toString());
            List<EntityDescriptor> list = getListOfIdpMetadata(inputStream);
            for (EntityDescriptor ed : list) {
                if (preferredEntityId.equals(ed.getEntityID())) {
                    this.entityDescriptor = ed;
                    break;
                }
            }
        } catch (IOException e) {
            throw new SAMLException("Unable to update SP Metadata.", e);
        }

        this.spMetadataObject = spMetadata;
        this.spSSODescriptor = this.entityDescriptor.getSPSSODescriptor(Constants.PROTOCOL);
        this.initialized = true;

        return this;
    }

    public static SPMetadata getInstance() {
        if (instance == null) {
            instance = new SPMetadata();
        }
        return instance;
    }

    /**
     * @return The entityID of the Mendix Service Provider
     * @throws SAMLException
     */
    public String getEntityID() throws SAMLException {
        if (!this.initialized)
            throw new SAMLException("The SPMetadata has not been initialized.");

        return this.entityDescriptor.getEntityID();
    }

    /**
     * Get the default assertion consumer service. If there is no default, the first is selected.
     *
     * @throws SAMLException
     */
    public AssertionConsumerService getDefaultAssertionConsumerService() throws SAMLException {
        if (!this.initialized)
            throw new SAMLException("The SPMetadata has not been initialized.");

        AssertionConsumerService service = this.spSSODescriptor.getDefaultAssertionConsumerService();
        if (service != null)
            return service;
        if (this.spSSODescriptor.getAssertionConsumerServices().isEmpty())
            throw new IllegalStateException("No AssertionConsumerServices defined in SP metadata");

        return this.spSSODescriptor.getAssertionConsumerServices().get(0);
    }

    /**
     * @param index
     * @return The location (URL) of {@link AssertionConsumerService} no. <code>index</code> at the service provider
     * @throws SAMLException
     */
    public String getAssertionConsumerServiceLocation(int index) throws SAMLException {
        if (!this.initialized)
            throw new SAMLException("The SPMetadata has not been initialized.");

        if (this.spSSODescriptor.getAssertionConsumerServices().size() > index) {
            AssertionConsumerService consumerService = this.spSSODescriptor.getAssertionConsumerServices().get(index);
            return consumerService.getLocation();
        }
        return null;
    }

    /**
     * @return The location (URL) of {@link SingleSignOnService} at the service provider for HTTP-Redirect
     * @throws SAMLException
     */
    public String getSingleLogoutServiceHTTPRedirectLocation() throws SAMLException {
        if (!this.initialized)
            throw new SAMLException("The SPMetadata has not been initialized.");

        for (SingleLogoutService singleLogoutService : this.spSSODescriptor.getSingleLogoutServices()) {
            if (SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(singleLogoutService.getBinding())) {
                return singleLogoutService.getLocation();
            }
        }
        return null;
    }

    /**
     * @return The response location (URL) of {@link SingleLogoutService} at the service provider for HTTP-Redirect
     * @throws SAMLException
     */
    public String getSingleLogoutServiceHTTPRedirectResponseLocation() throws SAMLException {
        if (!this.initialized)
            throw new SAMLException("The SPMetadata has not been initialized.");

        for (SingleLogoutService singleLogoutService : this.spSSODescriptor.getSingleLogoutServices()) {
            if (SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(singleLogoutService.getBinding())) {
                return singleLogoutService.getResponseLocation();
            }
        }
        return null;
    }

    /**
     * @return The location (URL) of {@link SingleLogoutService} at the service provider for SOAP
     * @throws SAMLException
     */
    public String getSingleLogoutServiceSOAPLocation() throws SAMLException {
        if (!this.initialized)
            throw new SAMLException("The SPMetadata has not been initialized.");

        for (SingleLogoutService singleLogoutService : this.spSSODescriptor.getSingleLogoutServices()) {
            if (SAMLConstants.SAML2_SOAP11_BINDING_URI.equals(singleLogoutService.getBinding())) {
                return singleLogoutService.getLocation();
            }
        }
        return null;
    }

    /**
     * @return The location (URL) of {@link SingleLogoutService} at the service provider for POST
     * @throws SAMLException
     */
    public String getSingleLogoutServiceHTTPPostLocation() throws SAMLException {
        if (!this.initialized)
            throw new SAMLException("The SPMetadata has not been initialized.");

        for (SingleLogoutService singleLogoutService : this.spSSODescriptor.getSingleLogoutServices()) {
            if (SAMLConstants.SAML2_POST_BINDING_URI.equals(singleLogoutService.getBinding())) {
                return singleLogoutService.getLocation();
            }
        }
        return null;
    }

    /**
     * @return The response location (URL) of {@link SingleLogoutService} at the service provider for POST
     * @throws SAMLException
     */
    public String getSingleLogoutServiceHTTPPostResponseLocation() throws SAMLException {
        if (!this.initialized)
            throw new SAMLException("The SPMetadata has not been initialized.");

        for (SingleLogoutService singleLogoutService : this.spSSODescriptor.getSingleLogoutServices()) {
            if (SAMLConstants.SAML2_POST_BINDING_URI.equals(singleLogoutService.getBinding())) {
                return singleLogoutService.getResponseLocation();
            }
        }
        return null;
    }

    public IMendixObject getSpMetadataObject() {
        return this.spMetadataObject;
    }

    public String getEncryptionAlgorithm(IContext context) {
        return this.spMetadataObject.getValue(context, saml20.proxies.SPMetadata.MemberNames.EncryptionMethod.toString());
    }
}
