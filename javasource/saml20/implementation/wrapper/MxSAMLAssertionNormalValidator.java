package saml20.implementation.wrapper;

import com.mendix.core.Core;
import com.mendix.logging.ILogNode;
import org.opensaml.saml.common.assertion.AssertionValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import saml20.implementation.common.Constants;

/**
 * The validator is responsible for the "normal" strategy
 */
public class MxSAMLAssertionNormalValidator {
    private static final ILogNode _logNode = Core.getLogger(Constants.LOGNODE);

    public void validate() throws AssertionValidationException {
        _logNode.info("Normal validation...");
    }
}
