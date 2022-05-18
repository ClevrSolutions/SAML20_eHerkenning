package saml20.implementation.wrapper;

import org.opensaml.saml.saml2.core.RequestAbstractType;

public class MxSAMLRequest extends MxSAMLObject {

    private final RequestAbstractType request;
    private final String relayState;

    public MxSAMLRequest(RequestAbstractType obj, String relayState) {
        super(obj);
        this.request = obj;
        this.relayState = relayState;
    }

    public String getRelayState() {
        return this.relayState;
    }

    public String getID() {
        return this.request.getID();
    }

    public String getDestination() {
        return this.request.getDestination();
    }
}
