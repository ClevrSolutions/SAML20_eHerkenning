package saml20.implementation.binding;

import com.mendix.core.Core;
import com.mendix.logging.ILogNode;
import com.mendix.m2ee.api.IMxRuntimeRequest;
import com.mendix.m2ee.api.IMxRuntimeResponse;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.opensaml.saml.saml2.metadata.Endpoint;
import saml20.implementation.SAMLRequestContext;
import saml20.implementation.common.Constants;
import saml20.implementation.common.HTTPUtils;
import saml20.implementation.metadata.IdpMetadata.Metadata;
import saml20.implementation.wrapper.MxSAMLObject;
import saml20.proxies.SPMetadata;

import javax.servlet.http.HttpServletRequest;

public class PostBindingHandler implements BindingHandler {
    protected static final ILogNode _logNode = Core.getLogger(Constants.LOGNODE);

    private VelocityEngine engine;

    public PostBindingHandler() {
        this.engine = HTTPUtils.getEngine();
    }

    @Override
    public String getBindingURI() {
        return SAMLConstants.SAML2_POST_BINDING_URI;
    }

    @Override
    public void handle( IMxRuntimeRequest request, IMxRuntimeResponse response, SAMLRequestContext context, Metadata metadata, Endpoint destination, MxSAMLObject mxSamlObj, String relayState ) throws SAMLException {
        HttpServletRequest req = request.getHttpServletRequest();

        // BJHL 2015-05-28 If use encryption is false, we cannot sign since there is no credential
        // available. Fall back to old behaviour of the module, which was to not sign the request.
        // This looks weird to me, I don't know for sure whether this will be accepted everywhere.
        final boolean useEncryption = context.getSpMetadata().getSpMetadataObject().getValue(
                context.getIContext(), SPMetadata.MemberNames.UseEncryption.toString());
        if (useEncryption) {
            mxSamlObj.sign(context.getCredential(), context.getSpMetadata().getEncryptionAlgorithm(context.getIContext()));
        } else {
            _logNode.warn("NOT USING ENCRYPTION!");
        }
        String encodedMessage = mxSamlObj.toBase64();

        req.setAttribute("action", destination);
        if ( relayState != null ) {
            req.setAttribute(Constants.SAML_RELAYSTATE, relayState);
        }
        req.setAttribute(Constants.SAML_SAMLREQUEST, encodedMessage);

        try {
            MessageContext<SAMLObject> samlContext = mxSamlObj.buildMessageContext(mxSamlObj, context, metadata, destination, relayState, useEncryption);

            HTTPPostEncoder encoder = new HTTPPostEncoder();
            encoder.setVelocityEngine(engine);
            encoder.setVelocityTemplateId("/templates/saml2-post-binding.vm");
            encoder.setMessageContext(samlContext);
            encoder.setHttpServletResponse(response.getHttpServletResponse());
            encoder.initialize();
            encoder.encode();
        }
        catch(MessageEncodingException | ComponentInitializationException e) {
            throw new SAMLException(e);
        }
    }
}
