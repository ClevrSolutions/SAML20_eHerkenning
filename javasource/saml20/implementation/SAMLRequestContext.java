package saml20.implementation;

import com.mendix.m2ee.api.IMxRuntimeRequest;
import com.mendix.m2ee.api.IMxRuntimeResponse;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.ISession;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.security.credential.Credential;
import saml20.implementation.binding.BindingHandlerFactory;
import saml20.implementation.metadata.IdpMetadata;
import saml20.implementation.metadata.SPMetadata;
import saml20.implementation.security.SessionManager;
import saml20.implementation.wrapper.MxResource;

public class SAMLRequestContext {
	private final IMxRuntimeRequest request;
	private final IMxRuntimeResponse response;
	private final ISession currentSession;
	private final IdpMetadata idpMetadata;
	private final SPMetadata spMetadata;
	private final Credential credential;
	private final IContext context;
	private Throwable error = null;
	private final SessionManager sessionManager;
	private final BindingHandlerFactory bindingHandlerFactory;
	private final VelocityEngine engine;
	
	private String samlSessionID = null;
	private MxResource resource = null;

	public SAMLRequestContext( IContext context, IMxRuntimeRequest request, IMxRuntimeResponse response, IdpMetadata idpMetadata, SPMetadata spMetadata, Credential credential, SessionManager sessionManager, BindingHandlerFactory bindingHandlerFactory, VelocityEngine engine, ISession currentSession ) {
		this.context = context;
		this.request = request;
		this.currentSession = currentSession;
		this.response = response;
		this.idpMetadata = idpMetadata;
		this.spMetadata = spMetadata;
		this.credential = credential;
		this.sessionManager = sessionManager;
		this.bindingHandlerFactory = bindingHandlerFactory;
		this.engine = engine;
	}
	
	public void setSamlSessionID( String samlSessionID ) {
		this.samlSessionID = samlSessionID;
	}
	public void setResource( MxResource resource ) {
		this.resource = resource;
	}

	public void setError( Throwable error ) {
		this.error = error;
	}

	public IMxRuntimeRequest getRequest() {
		return this.request;
	}

	public IMxRuntimeResponse getResponse() {
		return this.response;
	}
	
	public ISession getCurrentSession() {
		return this.currentSession;
	}

	public IdpMetadata getIdpMetadata() {
		return this.idpMetadata;
	}

	public SPMetadata getSpMetadata() {
		return this.spMetadata;
	}

	/**
	 * @return the currently active MxCore context for IMendixObject interaction
	 */
	public IContext getIContext() {
		return this.context;
	}

	public Credential getCredential() {
		return this.credential;
	}

	public SessionManager getSessionManager() {
		return this.sessionManager;
	}

	public BindingHandlerFactory getBindingHandlerFactory() {
		return this.bindingHandlerFactory;
	}

	public Throwable getError() {
		return this.error;
	}

	public VelocityEngine getEngine() {
		return this.engine;
	}
	
	public String getSAMLSessionID() {
		return this.samlSessionID;
	}
	public MxResource getResource() {
		return this.resource;
	}

}
