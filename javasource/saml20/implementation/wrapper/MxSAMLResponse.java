package saml20.implementation.wrapper;

import com.mendix.core.Core;
import com.mendix.logging.ILogNode;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IMendixIdentifier;
import com.mendix.systemwideinterfaces.core.IMendixObject;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.security.credential.Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import saml20.implementation.common.Constants;
import saml20.implementation.common.Constants.ValidationLevel;
import saml20.implementation.common.MendixUtils;
import saml20.implementation.metadata.IdpMetadata;
import saml20.proxies.EntityDescriptor;
import saml20.proxies.SAMLRequest;
import saml20.proxies.SSOConfiguration;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;

public class MxSAMLResponse extends MxSAMLObject {
    private static final ILogNode _logNode = Core.getLogger(Constants.LOGNODE);

    private final Response response;

    private MxSAMLAssertion assertion;

    public MxSAMLResponse(Response response) {
        super(response);
        _logNode.debug("Creating response object based on response: " + SerializeSupport.prettyPrintXML(response.getDOM()));
        this.response = response;
    }

    protected void validateResponse(String requestId, String expectedDestination, boolean allowPassive) throws SAMLException {
        String statusCode = this.response.getStatus().getStatusCode().getValue();
        String msg = "";

        // TODO: verify
        if (!StatusCode.SUCCESS.equals(statusCode)) {

            StatusCode is = this.response.getStatus().getStatusCode().getStatusCode();
            if (is == null || !(StatusCode.NO_PASSIVE.equals(is.getValue()) && allowPassive)) {
                msg = this.response.getStatus().getStatusMessage() == null ? "" : this.response.getStatus().getStatusMessage().getMessage();
                throw new SAMLException("Got StatusCode " + statusCode + (is == null ? "" : "/" + is.getValue()) + " should be " + StatusCode.SUCCESS + ". Message: [" + msg + "]  ID:[" + this.response.getID() + "]");
            }
        }
        if (!isDestinationOK(expectedDestination)) {
            throw new SAMLException("Wrong destination. Expected " + expectedDestination + ", was " + this.response.getDestination() + " ID:[" + this.response.getID() + "]");
        }

        if (requestId != null && !requestId.equals(this.response.getInResponseTo())) {
            throw new SAMLException("Wrong InResponseTo. Expected " + requestId + ", was " + this.response.getInResponseTo() + " ID:[" + this.response.getID() + "]");
        }

    }

    public void validateResponse(String expectedDestination, IdpMetadata metadata, String entityId, boolean allowPassive) throws SAMLException {
        validateResponse(null, expectedDestination, allowPassive);


        if (!hasSignature() && isPassive() && allowPassive) {
            return;
        }

        if (hasSignature() || isPassive()) {
            boolean valid = false;
            for (X509Certificate certificate : metadata.getSigningCertificates(entityId)) {
                if (verifySignature(certificate)) {
                    valid = true;
                    break;
                }
            }

            // Fall back to validate against all other certificates
            if (!valid) {
                for (X509Certificate certificate : metadata.getCertificates(entityId)) {
                    if (verifySignature(certificate)) {
                        valid = true;
                        break;
                    }
                }

                if (!valid) {
                    // none of the available certificates matched the signature, or other failure
                    throw new SAMLException("The response is not signed correctly" + " ID:[" + this.response.getID() + "]");
                }
            }
        }

        // if the full response does not have a signature and it is not a passive response
        else {
            if (!this.response.getAssertions().isEmpty()) {
                boolean valid = false;

                for (X509Certificate certificate : metadata.getSigningCertificates(entityId)) {
                    if (getAssertion(null).verifySignature(certificate)) {
                        valid = true;
                        break;
                    }
                }

                // Fall back to validate against all other certificates
                if (!valid) {
                    for (X509Certificate certificate : metadata.getCertificates(entityId)) {
                        if (getAssertion(null).verifySignature(certificate)) {
                            valid = true;
                            break;
                        }
                    }
                    if (!valid)
                        throw new SAMLException("The assertion is not signed correctly");
                }
            }
        }
    }

    /**
     * Resolve the IdP Entity id.  The preferred resolution is to retrieve the SSOConfig and EntityDescriptor by the corresponding SAML request.
     * If nothing has been found, it will fallback on the Issuer from the XML message.
     *
     * @param context
     * @param correspondingSAMLRequest
     * @return
     * @throws SAMLException
     */
    public String getOrigalIdpEntityId(IContext context, SAMLRequest correspondingSAMLRequest) throws SAMLException {

        String issuerName = null;
        if (correspondingSAMLRequest != null) {
            IMendixIdentifier ssoConfigId = correspondingSAMLRequest.getMendixObject().getValue(context, SAMLRequest.MemberNames.SAMLRequest_SSOConfiguration.toString());
            if (ssoConfigId != null) {
                List<IMendixObject> result = MendixUtils.retrieveFromDatabase(context, "//%s[%s = $id]",
                        new HashMap<String, Object>() {{
                            put("id", ssoConfigId);
                        }},
                        EntityDescriptor.entityName,
                        SSOConfiguration.MemberNames.SSOConfiguration_PreferedEntityDescriptor.toString()
                );
            }
        }

        /*
         * Fallback necessary in case the SAML request is no longer valid, or unsolicited requests are allowed.
         */
        if (issuerName == null || issuerName.isEmpty()) {
            Issuer issuer = null;
            if (!this.response.getAssertions().isEmpty()) {
                issuer = this.response.getAssertions().get(0).getIssuer();
            }
            if (issuer == null) {
                issuer = this.response.getIssuer();
            }

            if (issuer != null)
                issuerName = issuer.getValue();
        }

        if (issuerName != null)
            return issuerName;

        throw new SAMLException("SAML Response does not contain a issuer, this is required for unsolicited Responses");

    }

    public boolean isDestinationOK(String destination) {
        if (this.response.getDestination() == null)
            return true;

        if (Constants.validationLevel == ValidationLevel.Loose)
            return true;
        else
            return this.response.getDestination() != null && this.response.getDestination().equals(destination);
    }

    public boolean isPassive() {
        if (this.response.getStatus() == null)
            return false;
        if (this.response.getStatus().getStatusCode() == null)
            return false;
        if (this.response.getStatus().getStatusCode().getStatusCode() == null)
            return false;
        return StatusCode.NO_PASSIVE.equals(this.response.getStatus().getStatusCode().getStatusCode().getValue());
    }

    /**
     * Get the response assertion.
     *
     * @param credential
     * @throws SAMLException
     */
    public MxSAMLAssertion getAssertion(Credential credential) throws SAMLException {
        // return the
        if (this.assertion != null) {
            return this.assertion;
        }

        if (credential != null) {
            MxSAMLAssertion assertionResult = MxSAMLEncryptedAssertion.decryptAssertion(this.response, credential, true);
            if(assertionResult != null) {
                return assertionResult;
            }
        }

        return MxSAMLAssertion.fromResponse(this.response);
    }

    public Response getResponse() {
        return this.response;
    }
}
