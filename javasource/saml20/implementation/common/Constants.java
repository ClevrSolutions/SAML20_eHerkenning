package saml20.implementation.common;

import com.mendix.core.Core;
import org.opensaml.saml.common.xml.SAMLConstants;
import saml20.implementation.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class Constants {

    public static final String LOGNODE = "SAML_SSO";
    public static final ValidationLevel validationLevel = ValidationLevel.Loose;
    public static final String CERTIFICATE_LOCATION = Core.getConfiguration().getTempPath().getAbsolutePath() + "/SAMLStore.keystore";
    public static final String CERTIFICATE_PASSWORD = saml20.proxies.constants.Constants.getKeystorePassword();
    // Used for output to the user
    public static final String ATTRIBUTE_ERROR = "ErrorMessage";
    public static final String ATTRIBUTE_EXCEPTION = "ErrorDetails";
    public static final String ATTRIBUTE_APPLICATION_LOCATION = "ApplicationLocation";
    public static final String ATTRIBUTE_APPLICATION_SSO_LOCATION = "ApplicationSSOLocation";
    public static final String ATTRIBUTE_IDPLIST = "idpList";
    // Protocol / binding constants for browsing through the bindings and endpoints
    public static final String PROTOCOL = SAMLConstants.SAML20P_NS;
    /**
     * This array determines which protocols are supported, the order of this array determines the priority in which it
     * is being processed.
     */

    //
    public static final String SAML_SAMLRESPONSE = "SAMLResponse";
    public static final String SAML_SAMLREQUEST = "SAMLRequest";
    public static final String SAML_RELAYSTATE = "RelayState";
    public static final String RELAYSTATE_SEPARATOR = "_";
    public static final String PROP_PASSIVE = "Passive";
    public static final int COOKIE_SECONDS_PER_YEAR = 60 * 60 * 24 * 365;
    public static final String HTTP_HEADER_PAOS_CONTENT_TYPE = "application/vnd.paos+xml";
    public static final String HTTP_HEADER_PAOS = "ver=\"urn:liberty:paos:2003-08\";\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\"";
    public static final String SAML2_BEARER_NS = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    public static final String SAML2_HoK_NS = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";
    public static final String ERROR_MESSAGE_NO_CONFIGURATION = "The application hasn't been properly configured to support Single Sign On.";
    public static Constants _instance = null;
    public final String DISCOVERY_ATTRIBUTE = "_idp_id";
    /**
     * SSO constants
     */
    public String SSO_PATH = "SSO/";
    public String SSO_ASSERTION_PATH = null;
    public String SSO_LOGOUT_PATH = null;
    public String SSO_DISCOVERY_PATH = null;
    public String SSO_DEFAULT_LOGINPAGE = null;
    public boolean SSO_DEFAULT_FIRST_IDP = true;
    // e.g. used in deeplinks: appname/sso/login?cont=link/profile
    public String SSO_CONTINUATION_PARAMETER = "cont";
    public boolean DISCOVERY_ALLOWED = true;
    public String DISCOVERY_LANDINGPAGE = "SSO/discovery";
    private String SP_CONSUMER_URI = null;
    private Constants() {

        Properties prop = new Properties();
        File f = new File(Core.getConfiguration().getResourcesPath().getAbsolutePath() + "/SAMLConfig.properties");
        try (FileInputStream input = new FileInputStream(f)) {
            // load a properties file
            prop.load(input);

        } catch (IOException ex) {
            Core.getLogger(LOGNODE).warn("Unable to load properties from resource file, continue using default values");
        }


        // get the property value and print it out
        this.SP_CONSUMER_URI = evaluateProperty(prop, "sso.uri", null);
        this.SSO_PATH = evaluateProperty(prop, "sso.path", "SSO/");
        this.SSO_ASSERTION_PATH = evaluateProperty(prop, "sso.path.assertion", "SSO/assertion");
        this.SSO_LOGOUT_PATH = evaluateProperty(prop, "sso.path.logout", "SSO/logout");
        this.SSO_DISCOVERY_PATH = evaluateProperty(prop, "sso.path.discovery", "SSO/discovery");
        this.SSO_CONTINUATION_PARAMETER = evaluateProperty(prop, "sso.path.continuation", "cont");
        //This option should default to null, by default we don't redirect anywhere just use whatever the MxCookie tells us
        this.SSO_DEFAULT_LOGINPAGE = evaluateProperty(prop, "sso.path.login", null);


        this.SSO_PATH = evaluateProperty(prop, "sso.path", "SSO/");

        this.SSO_DEFAULT_FIRST_IDP = Boolean.valueOf(evaluateProperty(prop, "sso.discovery.redirectToFirstIdP", "true"));
        this.DISCOVERY_ALLOWED = Boolean.valueOf(evaluateProperty(prop, "sso.discovery.allowed", "true"));
        this.DISCOVERY_LANDINGPAGE = evaluateProperty(prop, "sso.discovery.landingpage", "SSO/discovery");
    }

    public static Constants _getInstance() {
        if (_instance == null) {
            _instance = new Constants();
        }

        return _instance;
    }

    private static String evaluateProperty(Properties prop, String property, String defaultValue) {

        try {
            if (prop.containsKey(property)) {
                String value = prop.getProperty(property);

                if (value != null && !"".equals(value.trim()))
                    return value;
            }
        } catch (Exception e) {
            Core.getLogger(LOGNODE).warn("Unable to read property: " + property + ", using default value: " + defaultValue, e);
        }

        return defaultValue;
    }

    public static Map<SAMLAction, SAMLHandler> getHandlers() {
        Map<SAMLAction, SAMLHandler> handlers = new HashMap<SAMLAction, SAMLHandler>();

        handlers.put(SAMLAction.login, new LoginHandler());
        handlers.put(SAMLAction.logout, new LogoutHandler());
        handlers.put(SAMLAction.assertion, new ArtifactHandler());
        handlers.put(SAMLAction.metadata, new MetadataHandler());
        handlers.put(SAMLAction.discovery, new DiscoveryHandler());
        handlers.put(SAMLAction.delegatedAuthentication, new DelegatedAuthenticationHandler());

        return handlers;
    }

    /**
     * You could define another landing page here, for example: When you would like to redirect to '/SSO/' directly from
     * your index.html page by adding '<meta http-equiv="refresh" content="0;URL=/SSO/" />', you don't want to end up on
     * 'index.html' again.
     * <p>
     * By renaming this constant to '/index3.html', you'll land on index3 instead of index. Don't forget to add a
     * 'index3.html' to your theme in this case! (You can copy the contents from index.html to index3.html)
     */
    public static final String getLandingPage() {
        String constant = saml20.proxies.constants.Constants.getSSOLandingPage();
        String indexpage = "index.html", indexconfig = (constant != null ? constant.trim() : null);

        if (indexconfig != null) {
            if (indexconfig.startsWith("/"))
                indexconfig = indexconfig.substring(1);

            indexpage = indexconfig;
        }

        return indexpage;
    }

    public static final String[] getBindingURIs() {
        /*
         * If you encounter the error (most likely you are using Mac OSX and a Safari browser):
         * "MSIS7046: The SAML protocol parameter 'RelayState' was not found or not valid."
         * Setting this Boolean to true might help resolve this issue.
         *
         * By default we favour the Post binding as the maximum (message) size exceeds that of a Redirect binding
         * due to it using cookies and post information instead of URL parameters (redirect).
         *
         * The size constraint can especially be a factor when using encryption.
         *
         * Fix provided by Jasper van der Hoek on 20150608, implemented by Jaap Pulleman - 20150624.
         *
         */

        if (saml20.proxies.constants.Constants.getBindingURI_Redirect()) {
            return new String[]{SAMLConstants.SAML2_REDIRECT_BINDING_URI, SAMLConstants.SAML2_POST_BINDING_URI};
        } else {
            // the default
            return new String[]{SAMLConstants.SAML2_POST_BINDING_URI, SAMLConstants.SAML2_REDIRECT_BINDING_URI};
        }
    }

    public final String getSP_URI() {
        if (this.SP_CONSUMER_URI == null) {
            this.SP_CONSUMER_URI = Core.getConfiguration().getApplicationRootUrl();
            this.SP_CONSUMER_URI = URLUtils.ensureEndsWithSlash(this.SP_CONSUMER_URI);
        }

        return this.SP_CONSUMER_URI;
    }

    /**
     * You could define another login page here, for example when you configured the index.html page to redirect to
     * '/SSO/'
     * <p>
     * This page allows the user to open a default Mendix login page so he can access the application with his regular
     * credentials. The page opened from this location should contain a Mendix login page.
     * <p>
     * If you leave this constant empty the user will not get a button to open the default login page in case the SSO
     * action fails.
     */
    public final String getLoginPage() {
        try {
            //This option should default to null
            if (this.SSO_DEFAULT_LOGINPAGE == null) {
                Object constant = Core.getConfiguration().getConstantValue("SAML20.DefaultLoginPage");
                String loginconfig = (constant != null ? constant.toString().trim() : null);

                if (loginconfig != null && !loginconfig.isEmpty()) {
                    if (loginconfig.startsWith("/"))
                        loginconfig = loginconfig.substring(1);

                    this.SSO_DEFAULT_LOGINPAGE = loginconfig;
                }
            }
        } catch (Exception e2) {
            Core.getLogger(LOGNODE).debug("Unable to get the login page constant: 'SAML20.DefaultLoginPage'", e2);
        }

        return this.SSO_DEFAULT_LOGINPAGE;
    }

    /**
     * It is recommended to remove the sign out button, but if you choose to keep the sign out button the user will be
     * redirected to a page.
     * <p>
     * After signing out the user will be redirected to this location.
     */
    public final String getLogoutPage() {
        String constant = saml20.proxies.constants.Constants.getDefaultLogoutPage();
        String indexpage = this.SSO_PATH, indexconfig = (constant != null ? constant.trim() : null);

        if (indexconfig != null) {
            if (indexconfig.startsWith("/"))
                indexconfig = indexconfig.substring(1);

            indexpage = indexconfig;
        }

        return indexpage;
    }

    public enum SAMLAction {
        login, logout, assertion, metadata, discovery, delegatedAuthentication
    }

    public enum ValidationLevel {
        Strict, Normal, Loose
    }

}
