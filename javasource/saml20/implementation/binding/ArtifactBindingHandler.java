package saml20.implementation.binding;

import com.mendix.core.Core;
import com.mendix.logging.ILogNode;
import com.mendix.m2ee.api.IMxRuntimeRequest;
import com.mendix.m2ee.api.IMxRuntimeResponse;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.Endpoint;
import saml20.implementation.SAMLRequestContext;
import saml20.implementation.common.Constants;
import saml20.implementation.metadata.IdpMetadata.Metadata;
import saml20.implementation.wrapper.MxSAMLObject;

import java.io.IOException;

/**
 * This handler is for sending an Authorization request to an Artifact binding URI using a HTML redirect
 *
 * @author Jasper van der Hoek
 */
public class ArtifactBindingHandler implements BindingHandler {
    private final static ILogNode _logNode = Core.getLogger(Constants.LOGNODE);

    @Override
    public String getBindingURI() {
        return SAMLConstants.SAML2_ARTIFACT_BINDING_URI;
    }

    @Override
    public void handle(IMxRuntimeRequest request, IMxRuntimeResponse response, SAMLRequestContext context, Metadata metadata, Endpoint destination, MxSAMLObject mxSamlObj, String relayState) throws SAMLException {
        String requestURI = mxSamlObj.getRedirectURL(context, metadata, destination, relayState);

        if (_logNode.isDebugEnabled())
            _logNode.debug("redirectURL...:" + requestURI);

        try {
            response.getHttpServletResponse().sendRedirect(requestURI);
        } catch (IOException e) {
            throw new SAMLException("Unable to redirect to url: " + requestURI, e);
        }
    }

}
