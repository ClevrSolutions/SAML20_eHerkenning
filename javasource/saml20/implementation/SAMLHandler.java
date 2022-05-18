package saml20.implementation;

import com.mendix.core.Core;
import com.mendix.logging.ILogNode;
import org.opensaml.saml.common.SAMLException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import saml20.implementation.common.Constants;

public abstract class SAMLHandler {
	private static final ILogNode _logNode = Core.getLogger(Constants.LOGNODE);

	public abstract void handleRequest( SAMLRequestContext context ) throws SAMLException;

	protected void printTraceInfo( SAMLRequestContext context ) {
		if ( _logNode.isTraceEnabled() ) {
			StringBuilder builder = new StringBuilder();
			builder.append("Processing request: ").append(context.getRequest().getResourcePath()).append("\r\n - SAMLRequest: ").append(context.getRequest().getParameter("SAMLRequest")).append("\r\n - SAMLResponse: ").append(context.getRequest().getParameter(Constants.SAML_SAMLRESPONSE)).append("\r\n - RelayState: ").append(context.getRequest().getParameter(Constants.SAML_RELAYSTATE));
			_logNode.info(builder.toString());
		}
	}
}
