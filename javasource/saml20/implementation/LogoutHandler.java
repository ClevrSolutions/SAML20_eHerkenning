package saml20.implementation;

import com.mendix.core.Core;
import com.mendix.core.CoreException;
import com.mendix.logging.ILogNode;
import com.mendix.m2ee.api.IMxRuntimeRequest;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.ISession;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import saml20.implementation.binding.BindingHandler;
import saml20.implementation.common.Constants;
import saml20.implementation.common.HTTPUtils;
import saml20.implementation.common.SAMLUtil;
import saml20.implementation.metadata.IdpMetadata.Metadata;
import saml20.implementation.security.SAMLSessionInfo;
import saml20.implementation.wrapper.MxSAMLLogoutRequest;
import saml20.implementation.wrapper.MxSAMLLogoutResponse;
import saml20.implementation.wrapper.MxSAMLRequest;
import saml20.proxies.SAMLRequest;

import java.io.IOException;

public class LogoutHandler extends SAMLHandler {
    private static final ILogNode _logNode = Core.getLogger(Constants.LOGNODE);

    @Override
    public void handleRequest(SAMLRequestContext context) throws SAMLException {
        printTraceInfo(context);
        ISession mxSession = null;
        try {
            IMxRuntimeRequest request = context.getRequest();
            mxSession = context.getSessionManager().getSessionFromRequest(request);

            /*
             * There are three different scenario's in which the browser uses this handler:
             *  1. A user wants to log out here, so we need to do a logout request
             *  2. The logout process is complete, we receive a logout response
             *  3. The user has logged out in some other app, we get a logout request from the IDP
             */
            boolean isRequest = HTTPUtils.isSAMLRequest(request.getHttpServletRequest());
            boolean isResponse = HTTPUtils.isSAMLResponse(request.getHttpServletRequest());
            if (!isRequest && !isResponse) {
                // Scenario 1: neither request nor response -> user wants to log out
                handleUserLogout(context, request);
            } else if (isResponse) {
                // Scenario 2: we receive a response for a request we previously sent
                handleLogoutResponse(context, request);
            } else {
                // Scenario 3: we receive a request to log out a user from the idp
                handleLogoutRequest(context, request);
            }
        } catch (CoreException e) {
            _logNode.error("Failure during SAML logout", e);
            doMendixLogout(context, mxSession);
        }
    }

    public void handleUserLogout(SAMLRequestContext context, IMxRuntimeRequest request)
            throws CoreException, SAMLException {
        // Check that user is logged in...
        ISession session = context.getSessionManager().getSessionFromRequest(request);
        IContext mxContext = context.getIContext();
        SAMLSessionInfo sessionInfo = context.getSessionManager().isLoggedIn(session);
        if (sessionInfo == null) {
            // user appears not logged in via SAML, do regular logout
            _logNode.info("Not a SAML user, logging out anyway: " + (session != null ? session.getUser(mxContext).getName() : "no session"));
            doMendixLogout(context, session);
        } else {
            Metadata metadata = context.getIdpMetadata().getMetadata(sessionInfo.getEntityId());

            org.opensaml.saml.saml2.metadata.Endpoint logoutLocation = metadata.findLogoutEndpoint(Constants.getBindingURIs());
            if (logoutLocation == null) {
                String msg = "Could not find a valid IdP Logout location. Supported bindings: " + Constants.getBindingURIs() + ", available: " + metadata.getSingleLogoutServices();
                _logNode.info(msg);
                doMendixLogout(context, session);
            } else {
                _logNode.info("Logging " + session.getUser(mxContext).getName() + " out at " + logoutLocation.getLocation());

                MxSAMLLogoutRequest logoutRequest = MxSAMLLogoutRequest.buildLogoutRequest(request, logoutLocation.getLocation(), context.getSpMetadata().getEntityID(), context.getSessionManager());

                org.opensaml.saml.saml2.metadata.Endpoint singoffLocation = metadata.findLogoutEndpoint(Constants.getBindingURIs());

                BindingHandler bindingHandler = context.getBindingHandlerFactory().getBindingHandler(singoffLocation.getBinding());
                bindingHandler.handle(context.getRequest(), context.getResponse(), context, metadata, singoffLocation, logoutRequest, logoutRequest.getRelayState());

                // Store the request message for references
                // BJHL 2015-10-22 log the request after signing. request id contains leading underscore that must be stripped.
                String requestID = SAMLUtil.getRequestIDFromRelayState(logoutRequest.getID());
                SAMLUtil.logSAMLRequestMessage(context, requestID, logoutRequest, metadata.getSsoConfiguration());

                context.getSessionManager().logOut(session);
            }
        }
    }

    public void handleLogoutResponse(SAMLRequestContext context, IMxRuntimeRequest request)
            throws SAMLException, CoreException {
        // log out the currently logged in user
        ISession session = context.getSessionManager().getSessionFromRequest(request);
        doMendixLogout(context, session);

        // BJHL 2015-10-22 When an SSO logout completes successfully, we return here, so a response could be available. Let's log that
        // A bunch of info is needed to properly log a response
        LogoutResponse response = HTTPUtils.extractSAMLResponse(request.getHttpServletRequest());
        String requestID = SAMLUtil.getRequestIDFromRelayState(request.getParameter(Constants.SAML_RELAYSTATE));
        _logNode.info("Received LogoutResponse for request " + requestID);
        SAMLRequest correspondingSAMLRequest = SAMLUtil.retrieveCorrespondingRequest(context.getIContext(), requestID);
        String entityId = correspondingSAMLRequest.getSAMLRequest_SSOConfiguration().getSSOConfiguration_PreferedEntityDescriptor().getentityID();
        Metadata metadata = context.getIdpMetadata().getMetadata(entityId);
        SAMLUtil.logSAMLResponseMessage(context, correspondingSAMLRequest, response, null, metadata.getSsoConfiguration());
    }


    public void handleLogoutRequest(SAMLRequestContext context, IMxRuntimeRequest request) throws SAMLException, CoreException {
        String relayState = request.getParameter(Constants.SAML_RELAYSTATE);
        LogoutRequest logoutRequest = HTTPUtils.extractSAMLRequest(request.getHttpServletRequest());
        String idpEntityID = logoutRequest.getIssuer().getValue();
        _logNode.info("Received LogoutRequest from IDP (" + idpEntityID + "): " + logoutRequest.getID());

        // log out the currently logged in user
        ISession session = context.getSessionManager().getSessionFromRequest(request);
        context.getSessionManager().logOut(session);

        // construct logoutresponse for the idp
        MxSAMLLogoutResponse mxResponse = MxSAMLLogoutResponse.buildLogoutResponse(context, logoutRequest);

        // send the response
        Metadata metadata = context.getIdpMetadata().getMetadata(idpEntityID);
        Endpoint singoffLocation = metadata.findLogoutEndpoint(Constants.getBindingURIs());
        BindingHandler bindingHandler = context.getBindingHandlerFactory().getBindingHandler(singoffLocation.getBinding());
        bindingHandler.handle(context.getRequest(), context.getResponse(), context, metadata, singoffLocation, mxResponse, relayState);

        // log the messages
        SAMLUtil.logSAMLRequestMessage(context, logoutRequest.getID(), new MxSAMLRequest(logoutRequest, relayState), metadata.getSsoConfiguration());
        SAMLRequest requestObject = SAMLUtil.retrieveCorrespondingRequest(context.getIContext(), logoutRequest.getID());
        SAMLUtil.logSAMLResponseMessage(context, requestObject, mxResponse.getLogoutResponse(), null, metadata.getSsoConfiguration());
    }

    public void doMendixLogout(SAMLRequestContext context, ISession mxSession) throws SAMLException {
        try {
            context.getSessionManager().logOut(mxSession);
            String logoutUrl = Constants._getInstance().getSP_URI() + Constants._getInstance().getLogoutPage();
            context.getResponse().getHttpServletResponse().sendRedirect(logoutUrl);
        } catch (IOException e) {
            throw new SAMLException(e);
        }
    }
}
