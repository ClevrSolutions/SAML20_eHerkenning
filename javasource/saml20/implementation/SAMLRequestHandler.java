package saml20.implementation;

import com.google.common.collect.ImmutableList;
import com.mendix.core.Core;
import com.mendix.externalinterface.connector.RequestHandler;
import com.mendix.logging.ILogNode;
import com.mendix.m2ee.api.IMxRuntimeRequest;
import com.mendix.m2ee.api.IMxRuntimeResponse;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IMendixObject;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.config.impl.GlobalSecurityConfigurationInitializer;
import org.opensaml.xmlsec.impl.BasicSignatureSigningConfiguration;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import saml20.implementation.binding.BindingHandlerFactory;
import saml20.implementation.common.Constants;
import saml20.implementation.common.Constants.SAMLAction;
import saml20.implementation.common.HTTPUtils;
import saml20.implementation.common.SAMLUtil;
import saml20.implementation.metadata.IdpMetadata;
import saml20.implementation.metadata.SPMetadata;
import saml20.implementation.security.CredentialRepository;
import saml20.implementation.security.SessionManager;
import saml20.implementation.wrapper.MxResource;
import saml20.proxies.EncryptionMethod;

import javax.servlet.http.HttpServletResponse;
import java.io.Writer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SAMLRequestHandler extends RequestHandler {

	public static ILogNode _logNode = Core.getLogger(Constants.LOGNODE);
	private transient IdpMetadata idpMetadata;
	private transient SPMetadata spMetadata;
	private BindingHandlerFactory bindingHandlerFactory;
	private transient SessionManager sessionManager;
	private List<IMendixObject> ssoConfigurationList;
	private transient VelocityEngine engine;

	private Credential credential;

	private final Map<SAMLAction, SAMLHandler> handlers = new HashMap<SAMLAction, SAMLHandler>();
	private boolean initialized = false;
	private boolean requestHandlerRegistered = false;

	private static SAMLRequestHandler _instance = null;

	public static SAMLRequestHandler getInstance(IContext context) throws InitializationException {
		if (_instance == null)
			_instance = new SAMLRequestHandler(context);

		return _instance;
	}

	private SAMLRequestHandler(IContext context) throws InitializationException {
//        org.opensaml.DefaultBootstrap.bootstrap();
		InitializationService.initialize(); // TODO: JEROEN / verify if this is correct
		try {
			initServlet(context, false);
		} catch (Exception e) {
			_logNode.error("Unable to initialize the Servlet configuration", e);
		}

		this.engine = HTTPUtils.getEngine();
	}

	public void initServlet(IContext context, boolean forceReload) throws SAMLException, InitializationException {
		if (this.initialized == false || forceReload) {

			this.ssoConfigurationList = SAMLUtil.getActiveSSOConfig(context);
			IMendixObject spMetadataConfiguration = SAMLUtil.getMetadataConfig(context);

			this.handlers.clear();

			// Make sure the SP url is properly set in the configuration entity
//			if ( this.ssoConfigurationList != null ) {

			this.handlers.putAll(Constants.getHandlers());
			if (_logNode.isDebugEnabled())
				_logNode.debug("Found handlers: " + this.handlers);

			String entityId = spMetadataConfiguration.getValue(context, saml20.proxies.SPMetadata.MemberNames.EntityID.toString());
			if (entityId == null || entityId.isEmpty())
				throw new SAMLFeedbackException("There was no entity Id specified in the SP Metadata, please configure the Entity ID before using SSO.").addFeedbackMessage(Constants.ERROR_MESSAGE_NO_CONFIGURATION);


			this.bindingHandlerFactory = new BindingHandlerFactory();

			if (this.ssoConfigurationList != null) {
				this.idpMetadata = IdpMetadata.getInstance().updateConfiguration(context, this.ssoConfigurationList);
			}

			CredentialRepository credentialRepository = CredentialRepository.getInstance();
			credentialRepository.updateConfiguration(context, spMetadataConfiguration, this.idpMetadata);

			this.credential = credentialRepository.getCredential(Constants.CERTIFICATE_PASSWORD, entityId);

			this.sessionManager = SessionManager.getInstance(context).init(context, this.ssoConfigurationList);
			this.spMetadata = SPMetadata.getInstance().updateConfiguration(context, spMetadataConfiguration, credentialRepository);

			// initializes the various security configurations
			GlobalSecurityConfigurationInitializer gsci = new GlobalSecurityConfigurationInitializer();
			gsci.init();

			// set the signing algos
			BasicSignatureSigningConfiguration sigSignConfig = (BasicSignatureSigningConfiguration) SecurityConfigurationSupport.getGlobalSignatureSigningConfiguration();
			if (this.spMetadata.getEncryptionAlgorithm(context).equals(EncryptionMethod.SHA256WithRSA.toString())) {
				sigSignConfig.setSignatureReferenceDigestMethods(ImmutableList.of(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256));
				sigSignConfig.setSignatureReferenceDigestMethods(ImmutableList.of(SignatureConstants.ALGO_ID_DIGEST_SHA256));
			} else {
				sigSignConfig.setSignatureReferenceDigestMethods(ImmutableList.of(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1));
				sigSignConfig.setSignatureReferenceDigestMethods(ImmutableList.of(SignatureConstants.ALGO_ID_DIGEST_SHA1));
			}

			this.initialized = true;

			if (!this.requestHandlerRegistered) {
				Core.addRequestHandler(Constants._getInstance().SSO_PATH, this);
				Core.addRequestHandler(Constants._getInstance().SSO_PATH.toLowerCase(), this);

				Core.addRequestHandler(Constants._getInstance().SSO_LOGOUT_PATH, this);
				Core.addRequestHandler(Constants._getInstance().SSO_LOGOUT_PATH.toLowerCase(), this);

				Core.getLogger(Constants.LOGNODE).info("SAML SSO RequestHandler has been added to path '" + Constants._getInstance().SSO_PATH + "'");
				this.requestHandlerRegistered = true;
			}
		}
	}

	@Override
	public void processRequest(IMxRuntimeRequest request, IMxRuntimeResponse response, String arguments) {
		try {
			IContext context = Core.createSystemContext();
			initServlet(context, false);

			String[] resourceArgs = HTTPUtils.extractResourceArguments(request);

			//resourceArgs[0] = the action, decide on the default action
			if ("".equals(resourceArgs[0])) {
				if (request.getParameter(Constants.SAML_SAMLRESPONSE) == null)
					resourceArgs[0] = SAMLAction.login.toString();                //No SAML response let's assume we have a login

				else if (request.getParameter(Constants.SAML_SAMLRESPONSE) != null &&
						!"".equals(request.getParameter(Constants.SAML_SAMLRESPONSE)))
					resourceArgs[0] = SAMLAction.assertion.toString();                //We can find a SAML response, must be an assertion request
			}

			SAMLAction action = SAMLAction.valueOf(resourceArgs[0]);
			_logNode.debug("Start processing action (" + action + "/" + resourceArgs[0] + ") " + (request.getParameter(Constants.SAML_SAMLRESPONSE) == null ? "without SAMLResponse" : "with SAMLResponse"));

			if (this.handlers.containsKey(action)) {
				try {
					SAMLRequestContext samlContext = new SAMLRequestContext(context, request, response, this.idpMetadata, this.spMetadata, this.credential, this.sessionManager, this.bindingHandlerFactory, this.engine, this.getSessionFromRequest(request));

					SAMLHandler handler = this.handlers.get(action);
					handler.handleRequest(samlContext);
				} catch (Exception e) {
					handleError(response, e);
				}
			} else {
				_logNode.debug("Unsupported action: [" + resourceArgs[0] + "] was requested, only " + this.handlers.keySet() + " are supported.");
				throw new SAMLFeedbackException("Unsupported action was requested, only " + this.handlers.keySet() + " are supported.");
			}
		} catch (Exception e) {
			_logNode.error("Error occurred while making request: " + e.getMessage());
			handleError(response, e);
		}
	}

	public void requestDelegatedAuthentication(String samlSessionID, String resourceURL) throws SAMLException, InitializationException {

		IContext context = Core.createSystemContext();
		initServlet(context, false);

		SAMLRequestContext samlContext = new SAMLRequestContext(context, null, null, this.idpMetadata, this.spMetadata, this.credential, this.sessionManager, this.bindingHandlerFactory, this.engine, null);
		samlContext.setSamlSessionID(samlSessionID);
		samlContext.setResource(new MxResource(resourceURL));

		SAMLHandler handler = this.handlers.get(SAMLAction.delegatedAuthentication);
		handler.handleRequest(samlContext);

	}

	private void handleError(IMxRuntimeResponse response, Exception e) {
		String DEFAULT_MESSAGE = "Unable to validate the SAML message!";

		_logNode.error("Unable to validate Response, see SAMLRequest overview for detailed response. Error: " + e.getMessage(), e);

		VelocityContext ctx = new VelocityContext();

		if (_logNode.isTraceEnabled()) {
			ctx.put(Constants.ATTRIBUTE_ERROR, e.getMessage());
			ctx.put(Constants.ATTRIBUTE_EXCEPTION, SAMLUtil.stacktraceToString(e));
		} else if (e instanceof SAMLFeedbackException) {
			ctx.put(Constants.ATTRIBUTE_ERROR, ((SAMLFeedbackException) e).getFeedbackMessage());
			ctx.put(Constants.ATTRIBUTE_EXCEPTION, null);
		} else {
			ctx.put(Constants.ATTRIBUTE_ERROR, DEFAULT_MESSAGE);
			ctx.put(Constants.ATTRIBUTE_EXCEPTION, null);
		}

		if (Constants._getInstance().getLoginPage() != null && !Constants._getInstance().getLoginPage().isEmpty())
			ctx.put(Constants.ATTRIBUTE_APPLICATION_LOCATION, Constants._getInstance().getSP_URI() + Constants._getInstance().getLoginPage());

		ctx.put(Constants.ATTRIBUTE_APPLICATION_SSO_LOCATION, Constants._getInstance().getSP_URI() + Constants._getInstance().SSO_PATH);

		response.setContentType("text/html");
		response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);

		try {
			Writer writer = response.getWriter();
			this.engine.mergeTemplate("templates/saml2-error-result.vm", "UTF-8", ctx, writer);
			writer.flush();
		} catch (Exception e1) {
			_logNode.error("Unable to render error template", e1);
		}
	}
}
