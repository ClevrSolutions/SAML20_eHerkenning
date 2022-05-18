package saml20.implementation.binding;

import com.mendix.m2ee.api.IMxRuntimeRequest;
import com.mendix.m2ee.api.IMxRuntimeResponse;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.saml2.metadata.Endpoint;
import saml20.implementation.SAMLRequestContext;
import saml20.implementation.metadata.IdpMetadata.Metadata;
import saml20.implementation.wrapper.MxSAMLObject;

public interface BindingHandler {

    String getBindingURI();

    void handle(IMxRuntimeRequest req, IMxRuntimeResponse response, SAMLRequestContext context, Metadata metadata, Endpoint endpoint, MxSAMLObject mxSamlObj, String relayState) throws SAMLException;
}
