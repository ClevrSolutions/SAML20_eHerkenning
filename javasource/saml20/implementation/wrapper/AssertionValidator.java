package saml20.implementation.wrapper;

import org.opensaml.saml.common.assertion.AssertionValidationException;

public interface AssertionValidator {
    void validate() throws AssertionValidationException;
}
