package saml20.implementation.wrapper;

import com.mendix.core.Core;
import com.mendix.logging.ILogNode;
import org.joda.time.DateTime;
import org.opensaml.saml.common.assertion.AssertionValidationException;
import org.opensaml.saml.saml2.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import saml20.implementation.common.Constants;

import java.util.Arrays;
import java.util.List;


public class MxSAMLAssertion extends MxSAMLObject {
	private static final ILogNode _logNode = Core.getLogger(Constants.LOGNODE);

	private final Assertion assertion;

	public MxSAMLAssertion(Assertion assertion) {
		super(assertion);
		this.assertion = assertion;
	}

	public static MxSAMLAssertion fromResponse(Response response) {
		if (response.getAssertions().isEmpty()) {
			return null;
		}

		Assertion assertion = response.getAssertions().get(0);
		return new MxSAMLAssertion(assertion);
	}

	public Assertion getAssertion() {
		return this.assertion;
	}

	public void validateAssertion(String spEntityID, String spAssertionConsumerURL) throws AssertionValidationException {
		DateTime now = DateTime.now();
		List<AssertionValidator> validators = Arrays.asList(
				new MxSAMLAssertionGenericValidator(assertion.getVersion(), assertion.getID()),
				new MxSAMLAssertionStrictValidator(assertion.getConditions(), spEntityID, now),
				new MxSAMLAssertionSubjectValidator(assertion.getSubject(), spEntityID, spAssertionConsumerURL, assertion.getID(), assertion.getConditions(), now)
		);
		for(AssertionValidator validator : validators) {
			validator.validate();
		}
	}

	public String getSessionIndex() {
		String retVal = null;
		if (this.assertion != null && this.assertion.getAuthnStatements() != null) {
			if (this.assertion.getAuthnStatements().size() > 0) {
				// We only look into the first AuthnStatement
				AuthnStatement authnStatement = this.assertion.getAuthnStatements().get(0);
				retVal = authnStatement.getSessionIndex();
			}
		}
		return retVal;
	}

	public String getIssuer() {
		Issuer issuer = this.assertion.getIssuer();
		if (issuer == null)
			return null;

		return issuer.getValue();
	}

	public String getNameID() {
		Subject subject = this.assertion.getSubject();
		if (subject == null)
			return null;

		return subject.getNameID().getValue();
	}

	public String getNameIDFormat() {
		Subject subject = this.assertion.getSubject();
		if (subject == null)
			return null;

		return subject.getNameID().getFormat();
	}
}