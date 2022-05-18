package saml20.implementation.binding;

import org.opensaml.saml.common.xml.SAMLConstants;

import java.util.HashMap;
import java.util.Map;

public class BindingHandlerFactory {

    private final static Map<String, BindingHandler> handlers = new HashMap<String, BindingHandler>();

    public BindingHandlerFactory() {
        handlers.put(SAMLConstants.SAML2_ARTIFACT_BINDING_URI, new ArtifactBindingHandler());
        handlers.put(SAMLConstants.SAML2_POST_BINDING_URI, new PostBindingHandler());
        handlers.put(SAMLConstants.SAML2_REDIRECT_BINDING_URI, new RedirectBindingHandler());
    }

    public BindingHandler getBindingHandler(String bindingName) throws IllegalArgumentException {
        BindingHandler handler = handlers.get(bindingName);
        if (handler == null) {
            throw new IllegalArgumentException(bindingName);
        } else {
            return handler;
        }
    }

}
