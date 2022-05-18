package saml20.implementation.wrapper;


public class MxResource {

    private final String resourceURL;

    public MxResource(String resourceURL) {
        this.resourceURL = resourceURL;
    }

    public String getResourceURL() {
        return this.resourceURL;
    }

}
