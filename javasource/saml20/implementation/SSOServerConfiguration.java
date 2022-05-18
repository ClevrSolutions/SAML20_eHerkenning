package saml20.implementation;

import com.mendix.core.Core;
import com.mendix.systemwideinterfaces.core.IContext;
import saml20.implementation.common.Constants;

public class SSOServerConfiguration {

	/**
	 * starts the Single Sign On servlet
	 * 
	 * @param context
	 */
	public static void start( IContext context ) {
		try {
			SAMLRequestHandler.getInstance(context);
		}
		catch( Exception e ) {
			Core.getLogger(Constants.LOGNODE).error("Unable to add RequestHandler to path '" + Constants._getInstance().SSO_PATH + "': ", e);
		}
	}
}
