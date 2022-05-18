package saml20.implementation.security;

import com.mendix.core.Core;
import com.mendix.core.CoreException;
import com.mendix.externalinterface.connector.RequestHandler;
import com.mendix.logging.ILogNode;
import com.mendix.m2ee.api.IMxRuntimeRequest;
import com.mendix.m2ee.api.IMxRuntimeResponse;
import com.mendix.systemwideinterfaces.core.*;
import mxmodelreflection.proxies.Microflows;
import mxmodelreflection.proxies.MxObjectMember;
import mxmodelreflection.proxies.MxObjectType;
import org.opensaml.saml.common.SAMLException;
import saml20.implementation.SAMLFeedbackException;
import saml20.implementation.SAMLRequestContext;
import saml20.implementation.SAMLRequestHandler;
import saml20.implementation.common.*;
import saml20.implementation.common.Constants.SAMLAction;
import saml20.implementation.wrapper.MxSAMLAssertion;
import saml20.proxies.*;
import system.proxies.TokenInformation;
import system.proxies.User;
import system.proxies.UserRole;

import javax.servlet.http.HttpServletResponse;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class SessionManager {

	public static final String HTTP_HEADER_USER_AGENT = "User-Agent";
	public static final String AUTH_TOKEN_COOKIE_NAME = "AUTH_TOKEN";

	private static ILogNode _logNode = Core.getLogger(Constants.LOGNODE);

	private Map<UUID, SAMLSessionInfo> activeSessions = new ConcurrentHashMap<UUID, SAMLSessionInfo>();

	private ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();

	public class Configuration {

		private final String userEntityName;
		private final String userPrincipleMemberName;
		private boolean createUsers;
		private IMendixObject defaultUserRoleObject;
		private boolean useCustomUserProvisioning;
		private boolean useCustomAfterSigninLogic;
		private String customProvisioningMicroflow;
		private String customAfterSigninMicroflow;
		private boolean enableMobileAuthToken;
		protected boolean allowDelegatedAuthentication;
		private List<IMendixObject> mxClaimMapList;

		@SuppressWarnings("serial")
		public Configuration( IContext context, String userEntityName, String userPrincipleMemberName, boolean createUsers, boolean useUserProvisioning,
				boolean useCustomAfterSigninLogic, String customProvisioningMicroflow, String customAfterSigninMicroflow, boolean allowDelegatedAuthentication, boolean enableMobileAuthToken, IMendixObject defaultUserRoleObject, IMendixObject ssoConfigObj ) {
			this.userEntityName = userEntityName;
			this.userPrincipleMemberName = userPrincipleMemberName;
			this.createUsers = createUsers;
			this.useCustomUserProvisioning = useUserProvisioning;
			this.useCustomAfterSigninLogic = useCustomAfterSigninLogic;
			this.customProvisioningMicroflow = customProvisioningMicroflow;
			this.customAfterSigninMicroflow = customAfterSigninMicroflow;
			this.enableMobileAuthToken = enableMobileAuthToken;
			this.defaultUserRoleObject = defaultUserRoleObject;
			this.allowDelegatedAuthentication = allowDelegatedAuthentication;

			/*
			 * Retrieve the full claim map with all the attribute mapping fields
			 */
			this.mxClaimMapList = MendixUtils.retrieveFromDatabase(context, "//%s[%s = $id][%s != empty][%s != empty]",
					new HashMap<String, Object>() {{
						put("id", ssoConfigObj.getId());
					}},
					ClaimMap.entityName,
					ClaimMap.MemberNames.ClaimMap_SSOConfiguration.toString(),
					ClaimMap.MemberNames.ClaimMap_Attribute.toString(),
					ClaimMap.MemberNames.ClaimMap_MxObjectMember.toString()
			);
		}
	}

	private HashMap<String, Configuration> configurationSet = new HashMap<String, Configuration>();

	private static SessionManager _instance = null;

	public static SessionManager getInstance( IContext context ) throws SAMLException {
		if ( _instance == null )
			_instance = new SessionManager(context);

		return _instance;
	}

	private SessionManager( IContext context ) throws SAMLException {
		this.executor.scheduleAtFixedRate(this.periodicTask, 1, 1, TimeUnit.MINUTES);

		init(context, null);
	}

	public SessionManager init( IContext context, List<IMendixObject> ssoConfigurationList ) throws SAMLException {
		try {
			String userEntityName, userPrincipleMemberName;
			IMendixObject defaultUserRoleObject;
			boolean createUsers = false,
					useCustomUserProvisioning = false,
					useCustomAfterSignIn = false,
					enableDelegatedAuth = false,
					enableMobileAuthToken = false;
			String customProvisioningMicroflow = null,
					customAfterSigninMicroflow = null;

			if ( ssoConfigurationList != null ) {
				for( IMendixObject ssoConfigObj : ssoConfigurationList ) {
					String entityId = SAMLUtil.getEntityIdForConfig(context, ssoConfigObj);
					if ( entityId != null ) {
						SSOConfiguration ssoConfig = SSOConfiguration.initialize(context, ssoConfigObj);
						// String entityAlias = ssoConfig.getAlias();

						/*
						 * Retrieve the entity type for the user that we want to use, and the username which we use to
						 * compare the principle name
						 */
						MxObjectType mxObjectType = ssoConfig.getSSOConfiguration_MxObjectType();
						if ( mxObjectType != null )
							userEntityName = mxObjectType.getCompleteName();
						else
							userEntityName = null;

						MxObjectMember mxObjectMember = ssoConfig.getSSOConfiguration_MxObjectMember();
						if ( mxObjectMember != null )
							userPrincipleMemberName = mxObjectMember.getAttributeName();
						else
							userPrincipleMemberName = null;

						UserRole role = ssoConfig.getSSOConfiguration_DefaultUserRoleToAssign();
						if ( role != null )
							defaultUserRoleObject = role.getMendixObject();
						else
							defaultUserRoleObject = null;

						Microflows provisioningMicroflow = ssoConfig.getSSOConfiguration_CustomUserProvisioningMicroflow();
						if (provisioningMicroflow != null)
							customProvisioningMicroflow = provisioningMicroflow.getCompleteName();
						else
							customProvisioningMicroflow = null;

						Microflows afterSigninMicroflow = ssoConfig.getSSOConfiguration_CustomAfterSigninMicroflow();
						if (afterSigninMicroflow != null)
							customAfterSigninMicroflow = afterSigninMicroflow.getCompleteName();
						else
							customAfterSigninMicroflow = null;

						createUsers = ssoConfig.getCreateUsers();
						useCustomUserProvisioning = ssoConfig.getUseCustomLogicForProvisioning();
						useCustomAfterSignIn = ssoConfig.getUseCustomAfterSigninLogic();
						enableDelegatedAuth = ssoConfig.getEnableDelegatedAuthentication();
						enableMobileAuthToken = ssoConfig.getEnableMobileAuthToken();

						this.configurationSet.put(entityId, new Configuration(context, userEntityName, userPrincipleMemberName, createUsers,
								useCustomUserProvisioning, useCustomAfterSignIn, customProvisioningMicroflow, customAfterSigninMicroflow, enableDelegatedAuth, enableMobileAuthToken, defaultUserRoleObject, ssoConfigObj));
					}
				}
			}
		}
		catch( CoreException e ) {
			throw new SAMLException(e);
		}

		return this;
	}

	Runnable periodicTask = new Runnable() {

		@Override
		public void run() {
			// Invoke method(s) to do the work
			evaluateActiveSessions();
		}
	};

	/**
	 * this method can be used to initialize an XAS session when the username is known and verified.
	 *
	 * @param request
	 * @param response
	 * @param ssoconfig
	 * @param assertion
	 * @param username
	 * @throws Exception
	 */
	public ISession createSession( String entityId, SAMLRequestContext samlContext, SAMLSessionInfo samlSession, String entityAlias, String relayState ) throws Exception {
		IMxRuntimeResponse response = samlContext.getResponse();

		try {
			_logNode.debug("Initializing new session for user '" + samlSession.getIUser().getName() + "'");

			Configuration config = this.configurationSet.get(entityId);

			IContext context = samlContext.getIContext();

			IMendixObject currentSession = null, newSession = null, currentUser = null, newUser = null;
			if( config.useCustomAfterSigninLogic && samlContext.getCurrentSession() != null ) {
				currentSession = samlContext.getCurrentSession().getMendixObject();
				currentUser = samlContext.getCurrentSession().getUser(context).getMendixObject();
			}

			String previousSessionID = null;
			if (samlContext.getCurrentSession() != null) {
				previousSessionID = samlContext.getCurrentSession().getId().toString();
			};

			ISession session = Core.initializeSession(samlSession.getIUser(), previousSessionID);

			if( config.useCustomAfterSigninLogic ) {
				newSession = session.getMendixObject();
				newUser = session.getUser(context).getMendixObject();

				IContext mxContext = Core.createSystemContext();
				if (config.customAfterSigninMicroflow != null && !config.customAfterSigninMicroflow.equals("")) {
					Core.microflowCall(config.customAfterSigninMicroflow)
							.inTransaction(true)
							.withParam("PreviousSession", (currentSession == null ? null : system.proxies.Session.initialize(mxContext, currentSession).getMendixObject()))
							.withParam("PreviousUser", (currentUser == null ? null : User.initialize(mxContext, currentUser).getMendixObject()))
							.withParam("NewSession", system.proxies.Session.initialize(mxContext, newSession).getMendixObject())
							.withParam("NewUser", User.initialize(mxContext, newUser).getMendixObject())
							.execute(mxContext);
				} else {
					saml20.proxies.microflows.Microflows.customAfterSigninLogic(Core.createSystemContext(),
							(currentSession == null ? null : system.proxies.Session.initialize(mxContext, currentSession)), system.proxies.Session.initialize(mxContext, newSession),
							(currentUser == null ? null : User.initialize(mxContext, currentUser)), User.initialize(mxContext, newUser) );
				}
			}

			/**
			 * create cookies and redirect: String key, String value, String path, String domain, int expiry
			 */
			response.addCookie(Core.getConfiguration().getSessionIdCookieName(), session.getId().toString(), "/", "", -1,true);
			response.addHeader(RequestHandler.CSRF_TOKEN_HEADER, session.getCsrfToken());

			// Create authentication token for use in mobile apps
			if (config.enableMobileAuthToken) {
				String token = UUID.randomUUID().toString();
			    TokenInformation tokenInformation = new TokenInformation(samlContext.getIContext());
				tokenInformation.setToken(token);
				tokenInformation.setUserAgent(samlContext.getRequest().getHeader(HTTP_HEADER_USER_AGENT));
			    tokenInformation.setTokenInformation_User(User.initialize(samlContext.getIContext(), samlSession.getIUser().getMendixObject()));
			    tokenInformation.commit();
			    String authToken = token + ":" + samlSession.getIUser().getName();
				response.addCookie(AUTH_TOKEN_COOKIE_NAME, authToken,true);
			}
		    // end token generation

			// Third variable of addCookie is "Path" (based on source code) and setting this to "/" caused double
			// quotation marks to be added in the cloud (Linux?).
			// setting it to File.pathSeparator didn't resolve the issue in the Cloud. Removing the slash altogether did
			// resolve the issue.
			// -- JPU, 20150624
			String originURI = Constants._getInstance().SSO_PATH + SAMLAction.login + "?" + URLEncoder.encode(entityAlias, "UTF-8");
			response.addCookie("originURI",  originURI, "", "", Constants.COOKIE_SECONDS_PER_YEAR,true);


			UUID sessionIdTMP = samlSession.getSessionId(), sessionId = session.getId();

			// Remove the old sessionId reference from the map
			if (sessionIdTMP != null) {
				// can be null apparently (ticket #46552) so added check to avoid a nullpointerexception - JPU (Nov 16)
				this.activeSessions.remove(sessionIdTMP);
			}
			this.activeSessions.put(sessionId, samlSession);
			_logNode.trace("Updating User session: '" + samlSession.getIUser().getName() + "', from SessionId: " + sessionIdTMP + " to " + sessionId);

			// The lock should be released so the session will be removed whenever the user logs out.
			samlSession.releaseLock();

			// Determine where to redirect the user (either home/landing page or continuation URL)
			String redirectTo = Constants._getInstance().getSP_URI() + Constants.getLandingPage();
			String continuation = SAMLUtil.getContinuationFromRelayState(relayState);
			if ( continuation != null && !continuation.equals("") ) {
				redirectTo = Constants._getInstance().getSP_URI() + URLDecoder.decode(continuation, "UTF-8");
			}

			HTTPUtils.redirect(response, redirectTo);

			return session;
		}
		catch( Exception e ) {
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			throw new Exception("Single Sign On unable to create new session: " + e.getMessage(), e);
		}
	}

	public SAMLSessionInfo getUserFromPrincipal( String entityId, String principalValue, HashMap<String, Object> assertionAttributes, SSOConfiguration ssoConfig, MxSAMLAssertion mxSAMLAssertion ) throws Exception {
		// TODO workaround for mx5.5 since users are retrieved by the core in the system context, we have to initialize
		// the user in a separate context as well
		IContext mxContext = Core.createSystemContext();
		Configuration config = this.configurationSet.get(entityId);
		if ( config == null )
		{
			_logNode.debug("No valid SSO Configuration could be found for the provided Entity ID: " + entityId);
			throw new SAMLFeedbackException("No valid SSO Configuration could be found for the provided Entity ID.")
			.addFeedbackMessage(Constants.ERROR_MESSAGE_NO_CONFIGURATION);
		}

		if ( config.userEntityName != null && config.userPrincipleMemberName != null ) {

			// Try to find the user based on the principle name
			@SuppressWarnings("serial")
			List<IMendixObject> mxUserObjectList = MendixUtils.retrieveFromDatabase(mxContext, "//%s[%s = $principalValue]",
					new HashMap<String, Object>() {{
						put("principalValue", principalValue);
					}},
					config.userEntityName,
					config.userPrincipleMemberName
			);

			ArrayList<AssertionAttribute> astAttrList = null;

			IMendixObject mxUser = null;
			String userName = principalValue;

			// We have exactly 1 match, use the one we find
			if ( mxUserObjectList.size() == 1 ) {
				// success!
				mxUser = mxUserObjectList.get(0);
				_logNode.trace(mxUser.getValue(mxContext, User.MemberNames.Name.toString()) + "User found in the application");
			}

			/*
			 * We have multiple users that match the criteria
			 * This obviously can't happen for username, but since we facilitate searching on fields such as fullname,
			 * email phone, multiple matches are possible
			 */
			else if ( mxUserObjectList.size() > 1 ) {

				astAttrList = createAssertionAttributeList(mxContext, assertionAttributes, astAttrList);
				List<User> userList = new ArrayList<User>();
				for( IMendixObject obj : mxUserObjectList )
					userList.add(User.initialize(mxContext, obj));

				User user = saml20.proxies.microflows.Microflows.evaluateMultipleUserMatches(mxContext, ssoConfig, astAttrList, userList);

				// When the microflow returns a user, use that entity to login
				if ( user != null )
					mxUser = user.getMendixObject();

				// When nothing is being returned by the microflow stop processing the action
				else
					return null;
			}

			// No user found, and we allow creating one
			else if ( mxUserObjectList.size() == 0 && config.createUsers ) {
				_logNode.trace("No user retrieved, module configured to create a user.");

				mxUser = Core.instantiate(mxContext, config.userEntityName);
				mxUser.setValue(mxContext, User.MemberNames.Name.toString(), principalValue);
				mxUser.setValue(mxContext, config.userPrincipleMemberName, principalValue);
				mxUser.setValue(mxContext, User.MemberNames.Password.toString(), RandomPasswordGenerator.generatePswd(15, 20, 4, 4, 4));
				_logNode.trace(" Created(not committed) new user with username: " + principalValue);

				if ( config.defaultUserRoleObject != null ) {
					List<IMendixIdentifier> userroles = new ArrayList<IMendixIdentifier>();
					userroles.add(config.defaultUserRoleObject.getId());
					mxUser.setValue(mxContext, User.MemberNames.UserRoles.toString(), userroles);
					_logNode.trace("Associated userrole " + config.defaultUserRoleObject.getValue(mxContext, UserRole.MemberNames.Name.toString()));
				}
				else if ( config.useCustomUserProvisioning ) {
					_logNode.debug("No default userrole assigned to user: " + principalValue + ", we're assuming this will happen during custom logic");
				}
				else {
					String errorMessage = "Error in SSOConfiguration: No UserRole configured, therefore no new user can be created.";
					SAMLUtil.createLogLine(errorMessage, SSOLogResult.Failed);
					throw new SAMLFeedbackException(errorMessage).addFeedbackMessage(Constants.ERROR_MESSAGE_NO_CONFIGURATION);
				}
			}

			// No user found, and we are not creating one either
			else {
				return null;
			}

			for( IMendixObject mxClaimMap : config.mxClaimMapList ) {
				ClaimMap claimMap = ClaimMap.initialize(mxContext, mxClaimMap);

				try {
					MxObjectMember mxobjectMember = claimMap.getClaimMap_MxObjectMember();
					saml20.proxies.Attribute assertionAttribute = claimMap.getClaimMap_Attribute();

					if ( assertionAttributes.containsKey(assertionAttribute.getName()) ) {
						Object value = assertionAttributes.get(assertionAttribute.getName());
						if ( value instanceof String[] ) {
							String listOfValues = new String();
							for( String s : (String[]) value ) {
								if ( !listOfValues.isEmpty() ) {
									listOfValues += ";";
								}
								listOfValues += s;
							}
							value = listOfValues;
						}
						mxUser.setValue(mxContext, mxobjectMember.getAttributeName(), value);
						_logNode.trace("Updated '" + mxobjectMember.getAttributeName() + "' with '" + assertionAttributes.get(assertionAttribute.getName()) + "'");
					}
				}
				catch( CoreException e ) {
					SAMLUtil.createLogLine("Errror while updating attribute: '" + e.getMessage() + "'", SSOLogResult.Failed);
					_logNode.error("Errror while updating attribute: " + e.getStackTrace().toString());
				}

			}
			userName = mxUser.getValue(mxContext, User.MemberNames.Name.toString());
			try {
				Core.commit(mxContext, mxUser);
				_logNode.trace(" User p:'" + principalValue + "'/u:'" + userName + "' committed");
			}
			catch (RuntimeException e) {
				_logNode.trace("An error occured while trying to commit the user entity: p:'" + principalValue + "'/u:'" + userName + "'");
				throw new SAMLFeedbackException("An error occured while trying to commit the user entity.", e).addFeedbackMessage("The authentication was successful, but your account could not be setup in this application with the provided information.");
			}

			IUser newuser = Core.getUser(mxContext, userName);

			SAMLSessionInfo samlSessionInfo = new SAMLSessionInfo(mxSAMLAssertion, entityId, config, newuser);
			samlSessionInfo.setDeleteLock();
			try {
				// custom login functionality
				if ( config.useCustomUserProvisioning ) {
					_logNode.trace(" Executing custom logic functionality for user p:'" + principalValue + "'/u:'" + userName + "'");

					UUID sessionId = UUID.randomUUID();
					while( this.activeSessions.containsKey(sessionId) )
						sessionId = UUID.randomUUID();

					samlSessionInfo.setSessionId(sessionId);
					this.activeSessions.put(sessionId, samlSessionInfo);

					IMendixObject samlSessionObject = Core.instantiate(mxContext, SAMLSession.entityName);
					samlSessionObject.setValue(mxContext, SAMLSession.MemberNames.SessionID.toString(), sessionId.toString());
					samlSessionObject.setValue(mxContext, SAMLSession.MemberNames.Username.toString(), newuser.getName());

					samlSessionInfo.setSAMLSessionID(sessionId.toString());

					// BJHL 2016-12-05 removed retain/release, which was introduced as a fix in r90 on 2014-07-31

					try {
						astAttrList = createAssertionAttributeList(mxContext, assertionAttributes, astAttrList);
						LoginFeedback feedback = null;
						if (config.customProvisioningMicroflow != null && !config.customProvisioningMicroflow.equals("")) {
							List<IMendixObject> astAttributes = astAttrList.stream().map(attr -> attr.getMendixObject()).collect(Collectors.toList());
							IMendixObject feedbackObj = Core.microflowCall(config.customProvisioningMicroflow)
									.inTransaction(true)
									.withParam("SSOConfiguration", ssoConfig.getMendixObject())
									.withParam("AssertionAttributeList", astAttributes)
									.withParam("SAMLSession", SAMLSession.initialize(mxContext, samlSessionObject).getMendixObject())
									.withParam("User", User.initialize(mxContext, mxUser).getMendixObject())
									.execute(mxContext);
							feedback = feedbackObj != null ? LoginFeedback.initialize(mxContext, feedbackObj) : null;
						} else {
							feedback = saml20.proxies.microflows.Microflows.customUserProvisioning(mxContext, SAMLSession.initialize(mxContext, samlSessionObject),
									User.initialize(mxContext, mxUser), ssoConfig, astAttrList );
						}

						if ( feedback != null ) {

							if ( !feedback.getLoginAllowed(mxContext) ) {
								_logNode.info("Login aborted, CustomLoginLogic instructed that login is not allowed for user: p:'" + principalValue + "'/u:'" + userName + "'");
								String feedbackMsg = feedback.getFeedbackMessageHTML(mxContext);
								if ( feedbackMsg != null && !"".equals(feedbackMsg.trim()) ) {
									throw new SAMLFeedbackException(feedbackMsg);
								}
								else
									throw new SAMLFeedbackException("The authentication was successful, but your account could not be setup in this application with the provided information.");
							}
						}
					}
					catch( SAMLFeedbackException fe ) {
						throw fe;
					}
					catch( Exception e ) {
						throw new SAMLException("Exception occured while executing the customLoginLogic Microflow, the error was: " + e.getMessage(), e);
					}
				}

				// Get the user again, with the latest values from the just executed microflow
				samlSessionInfo.setUserRecord(Core.getUser(mxContext, userName));

				if ( ssoConfig.getEnableDelegatedAuthentication(mxContext) ) {
					String delAuthURL = ssoConfig.getDelegatedAuthenticationURL(mxContext);
					if ( delAuthURL != null && !"".equals(delAuthURL.trim()) )
						SAMLRequestHandler.getInstance(mxContext).requestDelegatedAuthentication(samlSessionInfo.getSamlSessionID(), delAuthURL);
					else
						_logNode.error("Invalid SSO configuration(" + ssoConfig.getAlias() + ") - Delegated authentication is enabled, but no URL has been specified.");
				}
			}
			catch( Exception e ) {
				samlSessionInfo.releaseLock();
				// BJHL 2016-12-05 removed retain/release, which was introduced as a fix in r90 on 2014-07-31
				throw e;
			}

			_logNode.trace(" Finished evaluating user with name: p:'" + principalValue + "'/u:'" + userName + "'");
			return samlSessionInfo;
		}
		else {
			if ( config.userEntityName != null ) {
				String errorMessage = "Error in SSOConfiguration: No User Entity has been configured.";
				SAMLUtil.createLogLine(errorMessage, SSOLogResult.Failed);
				throw new SAMLFeedbackException(errorMessage).addFeedbackMessage(Constants.ERROR_MESSAGE_NO_CONFIGURATION);
			}
			else {
				String errorMessage = "Error in SSOConfiguration: No User Entity attribute has been configured.";
				SAMLUtil.createLogLine(errorMessage, SSOLogResult.Failed);
				throw new SAMLFeedbackException(errorMessage).addFeedbackMessage(Constants.ERROR_MESSAGE_NO_CONFIGURATION);
			}
		}
	}

	/**
	 * Evaluate the list of assertions and build the list to pass into a microflow
	 *
	 * This function compares the size of the two list, only when this differs we'll rebuild the list.
	 *
	 * @param mxContext
	 * @param assertionAttributes
	 * @param currentList
	 * @return
	 */
	public ArrayList<AssertionAttribute> createAssertionAttributeList( IContext mxContext, HashMap<String, Object> assertionAttributes, ArrayList<AssertionAttribute> currentList ) {

		if ( currentList == null )
			currentList = new ArrayList<AssertionAttribute>(assertionAttributes.size());

		if ( currentList.size() < assertionAttributes.size() ) {
			for( Entry<String, Object> assertionAttributeEntry : assertionAttributes.entrySet() ) {
				Object value = assertionAttributeEntry.getValue();
				if ( value instanceof String ) {
					AssertionAttribute astAttr = new AssertionAttribute(mxContext);
					astAttr.setKey(assertionAttributeEntry.getKey());
					astAttr.setValue((String) value);
					currentList.add(astAttr);
				}
				else if ( value instanceof String[] ) {
					for( String iStr : (String[]) value ) {
						AssertionAttribute astAttr = new AssertionAttribute(mxContext);
						astAttr.setKey(assertionAttributeEntry.getKey());
						astAttr.setValue(iStr);
						currentList.add(astAttr);
					}
				}
				else
					_logNode.error("Unexpected value " + value + " for key: " + assertionAttributeEntry.getKey());
			}
		}

		return currentList;
	}

	public SAMLSessionInfo isLoggedIn( ISession mxSession ) {
		if ( mxSession == null )
			return null;

		return this.activeSessions.get(mxSession.getId());
	}

	public void logOut( ISession session ) {
		if ( session == null )
			return;

		if ( destoySAMLSessionInfo(session.getId()) )
			this.activeSessions.remove(session.getId());

		Core.logout(session);
	}

	public boolean destoySAMLSessionInfo( UUID sessionId ) {

		if ( this.activeSessions.containsKey(sessionId) ) {
			return this.activeSessions.get(sessionId).isRemovalAllowed();
		}

		return false;
	}


	private void evaluateActiveSessions() {
		try {
			List<UUID> sessionsToDestoy = new ArrayList<UUID>();
			for( Entry<UUID, SAMLSessionInfo> entry : this.activeSessions.entrySet() ) {
				UUID sessionId = entry.getKey();

				if ( Core.getSessionById(sessionId) == null ) {
					if ( _logNode.isDebugEnabled() )
						_logNode.debug("SessionManager - Attempting to clean up session: " + sessionId.toString() + " since the Mx Session is no longer active");

					if ( destoySAMLSessionInfo(sessionId) )
						sessionsToDestoy.add(sessionId);
				}
			}

			if ( _logNode.isDebugEnabled() )
				_logNode.debug("SessionManager - Removed sessions: " + sessionsToDestoy.toString());
			for( UUID sessionID : sessionsToDestoy )
				this.activeSessions.remove(sessionID);
		}
		catch( Exception e ) {
			_logNode.error(e);
		}
	}

	public SAMLSessionInfo getSessionDetails( IMxRuntimeRequest request ) throws SAMLException {
		try {
			ISession session = getSessionFromRequest(request);
			if ( session != null ) {
				return this.activeSessions.get(session.getId());
			}

			return null;
		}
		catch( CoreException e ) {
			throw new SAMLException(e);
		}
	}

	public SAMLSessionInfo getSessionDetails( String sessionId ) {
		if ( sessionId == null )
			return null;

		UUID sessionUuid = UUID.fromString(sessionId);

		if ( _logNode.isTraceEnabled() ) {

			for( UUID ses : this.activeSessions.keySet() ) {
				_logNode.trace("Active Session: " + ses);
			}

		}
		return this.activeSessions.get(sessionUuid);
	}

	public ISession getSessionFromRequest( IMxRuntimeRequest request ) throws CoreException {
		String sessionId = request.getCookie(Core.getConfiguration().getSessionIdCookieName());
		if ( sessionId == null )
			return null;

		UUID curUUID = UUID.fromString(sessionId);
		ISession session = Core.getSessionById(curUUID);

		if ( session == null || !session.isInteractive() )
			return null;

		return session;
	}

}