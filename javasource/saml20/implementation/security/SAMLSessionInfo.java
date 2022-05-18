package saml20.implementation.security;

import com.google.common.collect.ImmutableList;
import com.mendix.systemwideinterfaces.core.IUser;
import org.apache.http.HttpHeaders;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.config.SocketConfig;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;
import org.apache.http.ssl.SSLContexts;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.saml2.core.NameID;
import saml20.implementation.common.SAMLUtil;
import saml20.implementation.security.SessionManager.Configuration;
import saml20.implementation.wrapper.MxSAMLAssertion;

import javax.net.ssl.SSLContext;
import java.security.*;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

public class SAMLSessionInfo {
	private String nameIDValue = null;
	private String format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
	private String sessionIndex = null;
	private String entityId = null;
	private MxSAMLAssertion assertion;
	private String SAMLToken = null;
	private IUser userRecord;

	public SAMLSessionInfo(MxSAMLAssertion assertion, String entityId, Configuration config, IUser user) {
		updateInformation(assertion, entityId, config, user);
	}

	public void updateInformation(MxSAMLAssertion assertion, String entityId, Configuration config, IUser user) {
		this.userRecord = user;

		if (assertion.getAssertion().getSubject() != null && assertion.getAssertion().getSubject().getNameID() != null) {
			this.nameIDValue = assertion.getAssertion().getSubject().getNameID().getValue();
			this.format = assertion.getAssertion().getSubject().getNameID().getFormat();
		}
		this.sessionIndex = assertion.getSessionIndex();
		this.entityId = entityId;

		if (config.allowDelegatedAuthentication)
			this.assertion = assertion;
		else
			this.assertion = null;
	}

	public NameID getNameID() {
		NameID nameID = SAMLUtil.buildXMLObject(NameID.class);
		nameID.setValue(this.nameIDValue);
		nameID.setFormat(this.format);

		return nameID;
	}

	public String getSessionIndex() {
		return this.sessionIndex;
	}

	public String getEntityId() {
		return this.entityId;
	}

	public MxSAMLAssertion getAssertion() {
		return this.assertion;
	}

	public void setSAMLToken(String SAMLtoken) {
		this.SAMLToken = SAMLtoken;
	}

	public String getSAMLToken() {
		return this.SAMLToken;
	}

	private HttpClient httpClient = null;
	private boolean preventRemoval;
	private UUID SessionId = null;
	private String samlSessionID = null;

	/**
	 * Sets up the SSL parameters of a connection to the WSP, including the client certificate and server certificate
	 *
	 * @throws SAMLException
	 */
	public HttpClient getClientConnection() throws SAMLException {
		if (this.httpClient == null) {
			KeyStore myTrustStore = CredentialRepository.getInstance().getSSLKeyStore();
			SSLContext sslContext;
			try {
				sslContext = SSLContexts.custom()
						.loadKeyMaterial(myTrustStore, System.getProperty("javax.net.ssl.keyStorePassword").toCharArray())
						.build();
			} catch (NoSuchAlgorithmException | KeyManagementException | KeyStoreException | UnrecoverableKeyException e) {
				throw new RuntimeException("Failed to initialize keystore", e);
			}

			// HttpClient5 code is not compatible (yet) with OpenSAML 3, so using HttpClient4 impl:
			SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(sslContext,
					new String[]{"TLSv1.2", "TLSv1.3"}, null, SSLConnectionSocketFactory.getDefaultHostnameVerifier());
			Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
					.register("http", PlainConnectionSocketFactory.getSocketFactory())
					.register("https", sslConnectionSocketFactory)
					.build();

			PoolingHttpClientConnectionManager clientConnectionManager = new PoolingHttpClientConnectionManager(registry);
			clientConnectionManager.setMaxTotal(100);
			clientConnectionManager.setDefaultMaxPerRoute(20);

			RequestConfig requestConfig = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD_STRICT)
					.setConnectTimeout(5000).setConnectionRequestTimeout(5000).setSocketTimeout(5000).build();

			httpClient = HttpClients.custom()
					.setDefaultSocketConfig(SocketConfig.custom().setSoTimeout(5000).build())
					.setDefaultHeaders(ImmutableList.of(
							new BasicHeader(HttpHeaders.USER_AGENT, "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.2.2) Gecko/20100316 Firefox/3.6.2"),
							new BasicHeader(HttpHeaders.ACCEPT_CHARSET, "UTF-8")
							)
					)
					.setDefaultRequestConfig(requestConfig)
					.setConnectionTimeToLive(1, TimeUnit.MINUTES)
					.setConnectionManager(clientConnectionManager)
					.build();
		}

		return this.httpClient;
	}

	/**
	 * Prevent the SAMLSessionInfo to be removed from the SAML SessionCache even though there might not be an active
	 * User Session found for this Session Record
	 */
	public void setDeleteLock() {
		this.preventRemoval = true;
	}

	/**
	 * Release the lock so this SAMLSession record can be processed normally in the Next evaluation run.
	 * When no user is found this SessionInfo object will be removed
	 */
	public void releaseLock() {
		this.preventRemoval = false;
	}

	public boolean isRemovalAllowed() {
		return !this.preventRemoval;
	}

	public void setSAMLSessionID(String sessionID) {
		this.samlSessionID = sessionID;
	}

	public String getSamlSessionID() {
		return this.samlSessionID;
	}

	/**
	 * Register the Session Id for the Mendix User Session
	 *
	 * @param SessionId
	 */
	public void setSessionId(UUID SessionId) {
		this.SessionId = SessionId;
	}

	/**
	 * @return the SessionId from the Mendix User Session
	 */
	public UUID getSessionId() {
		return this.SessionId;
	}

	public IUser getIUser() {
		return this.userRecord;
	}


	public void setUserRecord(IUser userRecord) {
		this.userRecord = userRecord;
	}
}