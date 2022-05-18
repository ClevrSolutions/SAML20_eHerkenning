package saml20.implementation.wrapper;

import com.mendix.core.Core;
import com.mendix.logging.ILogNode;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.assertion.AssertionValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import saml20.implementation.common.Constants;

public class MxSAMLAssertionGenericValidator implements AssertionValidator {
    private static final ILogNode _logNode = Core.getLogger(Constants.LOGNODE);

    private SAMLVersion version;
    private String id;

    public MxSAMLAssertionGenericValidator(SAMLVersion version, String id) {
        this.version = version;
        this.id = id;
    }

    public void validate() throws AssertionValidationException {
        // The SAML version must be 2.0
        if (!SAMLVersion.VERSION_20.equals(getVersion())) {
            String msg = "The assertion must be version 2.0. Was " + getVersion();
            _logNode.error(msg);
            throw new AssertionValidationException(msg);
        }
        // There must be an ID
        if (getId() == null) {
            String msg = "The assertion must contain an ID reference";
            _logNode.error(msg);
            throw new AssertionValidationException(msg);
        }
    }

    public SAMLVersion getVersion() {
        return version;
    }

    public String getId() {
        return id;
    }
}
