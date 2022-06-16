package eherkenning.implementation;

import java.security.KeyStore;
import java.util.HashMap;
import java.util.List;

import javax.annotation.Nonnull;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.impl.client.HttpClients;
import org.joda.time.DateTime;
import org.opensaml.messaging.context.InOutOperationContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.pipeline.httpclient.BasicHttpClientMessagePipeline;
import org.opensaml.messaging.pipeline.httpclient.HttpClientMessagePipeline;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.binding.security.impl.SAMLOutboundProtocolMessageSigningHandler;
import org.opensaml.saml.saml2.binding.decoding.impl.HttpClientResponseSOAP11Decoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HttpClientRequestSOAP11Encoder;
import org.opensaml.saml.saml2.core.Artifact;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.credential.Credential;
import org.opensaml.soap.client.http.AbstractPipelineHttpSOAPClient;
import org.opensaml.soap.common.SOAPException;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mendix.core.Core;
import com.mendix.http.HttpMethod;
import com.mendix.logging.ILogNode;
import com.mendix.m2ee.api.IMxRuntimeRequest;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IMendixIdentifier;
import com.mendix.systemwideinterfaces.core.IMendixObject;

import saml20.implementation.SAMLRequestContext;
import saml20.implementation.common.Constants;
import saml20.implementation.common.HTTPUtils;
import saml20.implementation.common.MendixUtils;
import saml20.implementation.common.SAMLUtil;
import saml20.implementation.metadata.IdpMetadata.Metadata;
import saml20.implementation.security.CredentialRepository;
import saml20.implementation.wrapper.MxSAMLResponse;
import saml20.proxies.EntityDescriptor;
import saml20.proxies.SAMLRequest;
import saml20.proxies.SSOConfiguration;

public class ArtifactResolver {
	// AS: Code inspired by
	// https://github.com/sunrongxin7666/OpenSAML-ref-project-demo-v3/blob/master/src/main/java/no/steras/opensamlbook/sp/ConsumerServlet.java

	private static Logger logger = LoggerFactory.getLogger(ArtifactResolver.class);
	private static final ILogNode _logNode = Core.getLogger(Constants.LOGNODE);
	static final String SAML_ART_PARAMETER = "SAMLart";

	public static MxSAMLResponse getResponse(SAMLRequestContext context) throws SAMLException {
		HttpServletRequest request = context.getRequest().getHttpServletRequest();
		if (ArtifactResolver.useSamlArt(request)) {
			return ArtifactResolver.resolveArtifactResponse(context);
		}
		return HTTPUtils.extract(context.getRequest().getHttpServletRequest());
	}

	private static boolean useSamlArt(HttpServletRequest request) {
		String samlArt = request.getParameter(SAML_ART_PARAMETER);
		boolean useSamlArt = request.getMethod().equals(HttpMethod.GET.toString()) && samlArt != null;
		logger.info("Use SAML Artifact: ", useSamlArt);
		return useSamlArt;
	}

	private static MxSAMLResponse resolveArtifactResponse(SAMLRequestContext context) throws SAMLException {
		final HttpServletRequest req = context.getRequest().getHttpServletRequest();
		final HttpServletResponse resp = context.getResponse().getHttpServletResponse();

		Credential credentials = context.getCredential();
		String idpEntityID = getOrigalIdpEntityId(context);
		String spEntityID = context.getSpMetadata().getEntityID();
		Metadata metadata = context.getIdpMetadata().getMetadata(idpEntityID);
		String artResolutionServiceLocation = metadata.getArtifactResolutionServiceLocation(idpEntityID);
		logger.info("Artifact received");
		Artifact artifact = buildArtifactFromRequest(req);
		logger.info("Artifact: " + artifact.getArtifact());

		// Start creating ArtifactResolve;
		ArtifactResolve artifactResolve = buildArtifactResolve(artifact, spEntityID, artResolutionServiceLocation);

		logger.info("ArtifactResolve: ");
		// OpenSAMLUtils.logSAMLObject(artifactResolve);

		// Send ArtifactResolve
		// After the SOAP message is sent, it will wait for the Response to return or time out synchronously.
		// When the Response returns, the SAML message can be obtained:
		ArtifactResponse artifactResponse = sendAndReceiveArtifactResolve(artifactResolve, resp, artResolutionServiceLocation, credentials);
		logger.info("ArtifactResponse received");
		// OpenSAMLUtils.logSAMLObject(artifactResponse);

		return getResponse(artifactResponse);
	}

	private static MxSAMLResponse getResponse(ArtifactResponse artifactResponse) {
		Response response = (Response) artifactResponse.getMessage();
		// OpenSAMLUtils.logSAMLObject(response);
		return new MxSAMLResponse(response);
	}

	/**
	 * Send ArtifactResolve using SOAP protocol
	 */
	private static ArtifactResponse sendAndReceiveArtifactResolve(final ArtifactResolve artifactResolve,
			HttpServletResponse servletResponse, String location, Credential credential) {
		try {
			MessageContext<ArtifactResolve> contextout = new MessageContext<ArtifactResolve>();
			contextout.setMessage(artifactResolve);
			// Add data signature to enhance security
			SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
			signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
			signatureSigningParameters.setSigningCredential(credential);
			signatureSigningParameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
			SecurityParametersContext securityParametersContext = contextout.getSubcontext(SecurityParametersContext.class, true);
			if (securityParametersContext != null) {
				securityParametersContext.setSignatureSigningParameters(signatureSigningParameters);
			}

			// Create InOutOperationContext to handle input and output information
			InOutOperationContext<ArtifactResponse, ArtifactResolve> context = new ProfileRequestContext<ArtifactResponse, ArtifactResolve>();
			context.setOutboundMessageContext(contextout);

			// In order to be able to send SOAP messages, you also need to set up the SOAP Client.
			// This Client will call the message handler, encoder and decoder to transmit the message
			AbstractPipelineHttpSOAPClient<SAMLObject, SAMLObject> soapClient = new AbstractPipelineHttpSOAPClient<SAMLObject, SAMLObject>() {
				@Nonnull
				protected HttpClientMessagePipeline newPipeline() throws SOAPException {
					// Create encoder and decoder for input and output
					HttpClientRequestSOAP11Encoder encoder = new HttpClientRequestSOAP11Encoder();
					HttpClientResponseSOAP11Decoder decoder = new HttpClientResponseSOAP11Decoder();
					// create pipeline
					BasicHttpClientMessagePipeline pipeline = new BasicHttpClientMessagePipeline(encoder, decoder);
					// Sign the output content
					pipeline.setOutboundPayloadHandler(new SAMLOutboundProtocolMessageSigningHandler());
					return pipeline;
				}
			};

			HttpClient client = getClient();
			soapClient.setHttpClient(client);
			soapClient.send(location, context);

			return context.getInboundMessageContext().getMessage();
		} catch (SecurityException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}

	}

	private static HttpClient getClient() {
		// AS: Based on example of https://dzone.com/articles/configuring-ssl-tls-connection-made-easy
		// Maybe implement timeout similar to saml20.implementation.security.SAMLSessionInfo.getClientConnection
		try {
			KeyStore trustStore = CredentialRepository.getInstance().getTrustStore();
			String trustManagerFactoryAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
			TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(trustManagerFactoryAlgorithm);
			trustManagerFactory.init(trustStore);

			KeyStore identityKs = CredentialRepository.getInstance().getKeystoreSP();
			char[] pass = Constants.CERTIFICATE_PASSWORD.toCharArray();
			String keyManagerFactoryAlgorithm = KeyManagerFactory.getDefaultAlgorithm();
			KeyManagerFactory identityKeyManagerFactory = KeyManagerFactory.getInstance(keyManagerFactoryAlgorithm);
			identityKeyManagerFactory.init(identityKs, pass);

			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(identityKeyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

			HttpClient httpClient = HttpClients.custom()
					.setSSLContext(sslContext)
					.setSSLHostnameVerifier(new DefaultHostnameVerifier())
					.build();
			return httpClient;

		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}


	static private String getOrigalIdpEntityId(SAMLRequestContext samlContext) throws SAMLException {
		// AS: Based on saml20.implementation.wrapper.MxSAMLResponse.getOrigalIdpEntityId(IContext,  SAMLRequest)
		IContext context = samlContext.getIContext();
		IMxRuntimeRequest request = samlContext.getRequest();
		String relayState = request.getParameter(Constants.SAML_RELAYSTATE);
		String requestID = SAMLUtil.getRequestIDFromRelayState(relayState);
		SAMLRequest correspondingSAMLRequest = SAMLUtil.retrieveCorrespondingRequest(context, requestID);

		String issuerName = null;
		if (correspondingSAMLRequest != null) {
			IMendixIdentifier ssoConfigId = correspondingSAMLRequest.getMendixObject().getValue(context,
					SAMLRequest.MemberNames.SAMLRequest_SSOConfiguration.toString());
			if (ssoConfigId != null) {
				List<IMendixObject> result = MendixUtils.retrieveFromDatabase(context, "//%s[%s = $id]",
						new HashMap<String, Object>() {
							{
								put("id", ssoConfigId);
							}
						}, EntityDescriptor.entityName,
						SSOConfiguration.MemberNames.SSOConfiguration_PreferedEntityDescriptor.toString());
				if (result.size() == 1) {
					IMendixObject entityName = result.get(0);
					issuerName = entityName.getValue(context, EntityDescriptor.MemberNames.entityID.toString());
				}
				// _logNode.info(result.get(0));
			}
		} else {
			_logNode.warn("no correspondingSAMLRequest");
		}
		return issuerName;
	}

	private static Artifact buildArtifactFromRequest(final HttpServletRequest req) {
		Artifact artifact = OpenSAMLUtils.buildSAMLObject(Artifact.class);
		artifact.setArtifact(req.getParameter(SAML_ART_PARAMETER));
		return artifact;
	}

	private static ArtifactResolve buildArtifactResolve(final Artifact artifact, String entityID, String location) {
		ArtifactResolve artifactResolve = OpenSAMLUtils.buildSAMLObject(ArtifactResolve.class);
		// Issuer The identity representation of the sender, the same as the issuer in AuthnRequest;
		Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
		issuer.setValue(entityID);
		artifactResolve.setIssuer(issuer);
		artifactResolve.setIssueInstant(new DateTime());
		artifactResolve.setID(OpenSAMLUtils.generateSecureRandomId());
		artifactResolve.setDestination(location);
		artifactResolve.setArtifact(artifact);
		artifactResolve.setVersion(SAMLVersion.VERSION_20);

		return artifactResolve;
	}

}
