package saml20.implementation.wrapper;

import com.mendix.m2ee.api.IMxRuntimeRequest;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.core.xml.Namespace;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.SessionIndex;
import org.opensaml.saml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml.saml2.core.impl.SessionIndexBuilder;
import saml20.implementation.common.Constants;
import saml20.implementation.common.SAMLUtil;
import saml20.implementation.security.SAMLSessionInfo;
import saml20.implementation.security.SessionManager;

public class MxSAMLLogoutRequest extends MxSAMLRequest {

	public MxSAMLLogoutRequest( RequestAbstractType obj, String relayState ) {
		super(obj, relayState);
	}

	public static MxSAMLLogoutRequest buildLogoutRequest( IMxRuntimeRequest request, String logoutServiceLocation, String issuerEntityId, SessionManager handler ) throws SAMLException {
		LogoutRequest logoutRequest = new LogoutRequestBuilder().buildObject();

		String relayState = Constants.RELAYSTATE_SEPARATOR + java.util.UUID.randomUUID();

		logoutRequest.setID(relayState);
		logoutRequest.setIssueInstant(new DateTime(DateTimeZone.UTC));
		logoutRequest.getNamespaceManager().registerNamespaceDeclaration(new Namespace(SAMLConstants.SAML20_NS, SAMLConstants.SAML20_PREFIX));
		logoutRequest.setDestination(logoutServiceLocation);
		logoutRequest.setReason("urn:oasis:names:tc:SAML:2.0:logout:user");
		logoutRequest.setIssuer(SAMLUtil.createIssuer(issuerEntityId));

		SAMLSessionInfo sessionInfo = handler.getSessionDetails(request);
		if ( sessionInfo != null ) {
			SessionIndex sessionIndex = new SessionIndexBuilder().buildObject();
			sessionIndex.setSessionIndex(sessionInfo.getSessionIndex());

			logoutRequest.setNameID(sessionInfo.getNameID());
			logoutRequest.getSessionIndexes().add(sessionIndex);
		}

// JPU - 20200720 - validate() function was removed in OpenSAML3 library. Needs to implemented using standard XML Validation. Question is if this is even necessary.
//
//			_logNode.debug("Validate the logoutRequest...");
//			logoutRequest.validate(true);
//			_logNode.debug("...OK");



		return new MxSAMLLogoutRequest(logoutRequest, relayState);
	}
}
