package saml20.implementation.wrapper;

import com.mendix.core.Core;
import com.mendix.logging.ILogNode;
import org.joda.time.DateTime;
import org.opensaml.saml.common.assertion.AssertionValidationException;
import org.opensaml.saml.saml2.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import saml20.implementation.common.Constants;

import java.util.List;
import java.util.Optional;

public class MxSAMLAssertionSubjectValidator implements AssertionValidator {
    private static final ILogNode _logNode = Core.getLogger(Constants.LOGNODE);

    private Subject subject;
    private String spEntityID;
    private String spAssertionConsumerURL;
    private String assertionID;
    private Conditions conditions;
    private DateTime now;

    public MxSAMLAssertionSubjectValidator(Subject subject, String spEntityID, String spAssertionConsumerURL, String assertionID, Conditions conditions, DateTime now) {
        this.subject = subject;
        this.spEntityID = spEntityID;
        this.spAssertionConsumerURL = spAssertionConsumerURL;
        this.assertionID = assertionID;
        this.conditions = conditions;
        this.now = now;
    }

    public void validate() throws AssertionValidationException {
        if (subject != null) {
            Optional<String> audienceRestriction = getAudienceRestriction(conditions);
            if (audienceRestriction.isPresent()) {
                String audienceRestrictionName = audienceRestriction.get();

                /* Decision table with respective to "/"
                      SpEntityId	IDP-AudienceList	Result	Comment
                      TRUE	        TRUE	            TRUE	No Action
                      TRUE	        FALSE	            FALSE	"/" to be added
                      FALSE	        TRUE	            FALSE	IDP "/" should be removed
                      FALSE	        FALSE	            TRUE	No Action
                based on above decision table comparing without trailing "/" */

                if (spEntityID.endsWith("/")) {
                    spEntityID = spEntityID.substring(0, spEntityID.length()-1);
                }
                if (audienceRestrictionName.endsWith("/")) {
                    audienceRestrictionName = audienceRestrictionName.substring(0, audienceRestrictionName.length()-1);
                }

                if (!spEntityID.equals(audienceRestrictionName)) {
                    String msg = "Invalid Subject, this Assertion is not addressed to SP: " + audienceRestrictionName + " but should have been addressed to " + spEntityID;
                    _logNode.error(msg);
                    throw new AssertionValidationException(msg);
                }
            } else {
                String msg = "Invalid Subject, this Assertion has not been addressed to any SP. It should have been addressed to " + spEntityID;
                _logNode.error(msg);
                throw new AssertionValidationException(msg);
            }

            List<SubjectConfirmation> sConfirmations = subject.getSubjectConfirmations();
            for (SubjectConfirmation confirmation : sConfirmations) {
                SubjectConfirmationData confirmationData = confirmation.getSubjectConfirmationData();

                DateTime notBefore = confirmationData.getNotBefore();
                if (notBefore != null && (notBefore.isAfter(now) || notBefore.isEqual(now))) {
                    String msg = "Invalid Subject, this Assertion cannot be used before: " + notBefore.toString();
                    _logNode.error(msg);
                    throw new AssertionValidationException(msg);
                }

                DateTime notAfter = confirmationData.getNotOnOrAfter();
                if (notAfter != null && notAfter.isBefore(now)) {
                    String msg = "Invalid Subject, this Assertion cannot be used after: " + notAfter.toString();
                    _logNode.error(msg);
                    throw new AssertionValidationException(msg);
                }

                if (Constants.SAML2_BEARER_NS.equals(confirmation.getMethod())) {
                    if (!spAssertionConsumerURL.equals(confirmationData.getRecipient())) {
                        String msg = "Invalid Subject, this Assertion is sent to receipent: " + confirmationData.getRecipient() + " but should have been send to receipent: " + spAssertionConsumerURL;
                        _logNode.error(msg);
                        throw new AssertionValidationException(msg);
                    }
                } else if (Constants.SAML2_HoK_NS.equals(confirmation.getMethod())) {
                    //TODO validate the SAML certificates.
                }
            }
        } else {
            String msg = "Request: " + assertionID + " does not have a subject to validate the issuer and validity.";
            _logNode.warn(msg);
        }
    }

    public Subject getSubject() {
        return subject;
    }

    public String getSpEntityID() {
        return spEntityID;
    }

    public String getSpAssertionConsumerURL() {
        return spAssertionConsumerURL;
    }

    public String getAssertionID() {
        return assertionID;
    }

    public DateTime getNow() {
        return now;
    }

    public static Optional<String> getAudienceRestriction(Conditions conditions) {
        for (AudienceRestriction restriction : conditions.getAudienceRestrictions()) {
            for(Audience audience : restriction.getAudiences()) {
                return Optional.of(audience.getAudienceURI());
            }
        }
        return Optional.empty();
    }
}
