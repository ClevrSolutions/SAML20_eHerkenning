package saml20.implementation.wrapper;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.impl.LogoutResponseBuilder;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import saml20.implementation.SAMLRequestContext;
import saml20.implementation.common.Constants;
import saml20.implementation.common.SAMLUtil;

public class MxSAMLLogoutResponse extends MxSAMLObject {
	private LogoutResponse logoutResponse;
	
	public MxSAMLLogoutResponse(LogoutResponse obj) {
		super(obj);
		this.logoutResponse = obj;
	}

	public static MxSAMLLogoutResponse buildLogoutResponse(SAMLRequestContext context, LogoutRequest logoutRequest) throws SAMLException {
		StatusCode code = new StatusCodeBuilder().buildObject();
		code.setValue(StatusCode.SUCCESS);
		
		Status status = new StatusBuilder().buildObject();
		status.setStatusCode(code);
		
		LogoutResponse logoutResponse = new LogoutResponseBuilder().buildObject();
		logoutResponse.setID(Constants.RELAYSTATE_SEPARATOR + java.util.UUID.randomUUID().toString());
		logoutResponse.setIssueInstant(new DateTime(DateTimeZone.UTC));
		logoutResponse.setStatus(status);
		logoutResponse.setIssuer(SAMLUtil.createIssuer(context.getSpMetadata().getEntityID()));
		logoutResponse.setInResponseTo(logoutRequest.getID());
		
		return new MxSAMLLogoutResponse(logoutResponse);
	}

	public LogoutResponse getLogoutResponse() {
		return logoutResponse;
	}
}
