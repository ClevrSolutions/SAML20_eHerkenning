package saml20.implementation.wrapper;

import com.mendix.core.Core;
import com.mendix.logging.ILogNode;
import org.joda.time.DateTime;
import org.opensaml.saml.common.assertion.AssertionValidationException;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.Conditions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import saml20.implementation.common.Constants;

import java.util.List;

/**
 * The validator is responsible for the "strict" strategy
 */
public class MxSAMLAssertionStrictValidator implements AssertionValidator {
    private static final ILogNode _logNode = Core.getLogger(Constants.LOGNODE);

    private Conditions conditions;
    private String spEntityID;
    private DateTime now;

    public MxSAMLAssertionStrictValidator(Conditions conditions, String spEntityID, DateTime now) {
        this.conditions = conditions;
        this.spEntityID = spEntityID;
        this.now = now;
    }

    public void validate() throws AssertionValidationException {
        if (conditions != null) {
            // NotBefore can be ~200millis later than Now on the system
            // to overcome that, subtract one second from the NotBefore
            DateTime notBefore = null;
            if (conditions.getNotBefore() != null) {
                notBefore = conditions.getNotBefore().minusSeconds(1);
            }
            
            if (notBefore != null && (notBefore.isAfter(now) || notBefore.isEqual(now))) {
                String msg = "Assertion Conditions are not met. This request cannot be used before: " + notBefore.toString();
                throw new AssertionValidationException(msg);
            }

            DateTime notAfter = conditions.getNotOnOrAfter();
            if (notAfter != null && notAfter.isBefore(now)) {
                String msg = "Assertion Conditions are not met. This request cannot be used after: " + notAfter.toString();
                throw new AssertionValidationException(msg);
            }

            boolean anyAudiencesFound = false, appIsAudience = false;
            List<AudienceRestriction> audienceList = conditions.getAudienceRestrictions();
            for (AudienceRestriction restriction : audienceList) {
                for (Audience audience : restriction.getAudiences()) {
                    anyAudiencesFound = true;
                    String audienceURI= audience.getAudienceURI();

                    /* Decision table with respective to "/"
                         SpEntityId	IDP-AudienceList	Result	Comment
                         TRUE	   TRUE	                TRUE	No Action
                         TRUE	   FALSE	            FALSE	"/" to be added
                         FALSE	   TRUE	                FALSE	IDP "/" should be removed
                         FALSE	   FALSE	            TRUE	No Action
                      based on above decision table comparing without trailing "/" */

                    if (spEntityID.endsWith("/")) {
                        spEntityID = spEntityID.substring(0, spEntityID.length()-1);
                    }
                    if (audienceURI.endsWith("/")) {
                        audienceURI = audienceURI.substring(0, audienceURI.length()-1);
                    }

                    if (spEntityID.equals(audienceURI))
                        appIsAudience = true;
                }
            }

            if (anyAudiencesFound && !appIsAudience) {
                String msg = "Assertion Conditions are not met. This Service Provider application is not part of the designated audience list.";
                throw new AssertionValidationException(msg);
            }
        }
        else {
            _logNode.info("Conditions are empty or null");
        }
    }

    public Conditions getConditions() {
        return conditions;
    }

    public String getSpEntityID() {
        return spEntityID;
    }

    public DateTime getNow() {
        return now;
    }
}
