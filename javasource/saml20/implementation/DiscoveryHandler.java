package saml20.implementation;

import com.mendix.core.Core;
import com.mendix.logging.ILogNode;
import com.mendix.m2ee.api.IMxRuntimeResponse;
import org.apache.velocity.VelocityContext;
import org.opensaml.saml.common.SAMLException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import saml20.implementation.common.Constants;
import saml20.implementation.common.Constants.SAMLAction;
import saml20.implementation.common.HTTPUtils;
import saml20.implementation.metadata.IdpMetadata.Metadata;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class DiscoveryHandler extends SAMLHandler {
	private static final ILogNode _logNode = Core.getLogger(Constants.LOGNODE);

	@Override
	public void handleRequest( SAMLRequestContext context ) throws SAMLException {
		printTraceInfo(context);
		processDiscovery(context);
	}

	private static void processDiscovery( SAMLRequestContext context ) throws SAMLException {
		try {
			if ( Constants._getInstance().DISCOVERY_ALLOWED ) {
				Collection<Metadata> metadataList = context.getIdpMetadata().getAllMetaData();

				IMxRuntimeResponse response = context.getResponse();
				VelocityContext ctx = new VelocityContext();

				List<MetadataDescriptor> mdTable = new ArrayList<MetadataDescriptor>();
				for( Metadata metadata : metadataList ) {
					String url = Constants._getInstance().getSP_URI() + Constants._getInstance().SSO_PATH + SAMLAction.login + "?" + Constants._getInstance().DISCOVERY_ATTRIBUTE + "=" + metadata.getAlias(context.getIContext());
					MetadataDescriptor md = new MetadataDescriptor(url, metadata.getAlias(context.getIContext()));
					mdTable.add(md);
				}
				ctx.put(Constants.ATTRIBUTE_IDPLIST, mdTable);

				String loginPage = Constants._getInstance().getLoginPage();
				if ( loginPage != null && !loginPage.isEmpty() )
					ctx.put(Constants.ATTRIBUTE_APPLICATION_LOCATION, Constants._getInstance().getSP_URI() + loginPage);

				// ctx.put(Constants.ATTRIBUTE_APPLICATION_SSO_LOCATION, Constants.getSP_URI() + Constants.SSO_PATH);

				response.setContentType("text/html");
				response.setStatus(HttpServletResponse.SC_OK);

				try {
					Writer writer = response.getWriter();
					context.getEngine().mergeTemplate("templates/saml2-discovery-binding.vm", "UTF-8", ctx, writer);
					writer.flush();
				}
				catch( Exception e1 ) {
					_logNode.error("Unable to render discovery template", e1);
				}
			}
			else {
				String url = Constants._getInstance().getSP_URI() + Constants._getInstance().SSO_PATH + SAMLAction.login;

				String redirectedInfo = context.getRequest().getParameter("r");
				if ( redirectedInfo != null )
					HTTPUtils.sendMetaRedirect(context.getResponse(), URLDecoder.decode(redirectedInfo, "UTF-8"), null);

				else
					HTTPUtils.sendMetaRedirect(context.getResponse(), url, redirectedInfo);
			}
		}
		catch( IOException e ) {
			throw new SAMLException("Unable to write metadata back in the response", e);
		}
	}

	public static class MetadataDescriptor {
		private String url;
		private String title;

		public MetadataDescriptor( String url, String title ) {
			this.url = url;
			this.title = title;
		}

		public String getTitle() {
			return this.title;
		}

		public String getUrl() {
			return this.url;
		}
	}
}
