package saml20.implementation;

import org.owasp.html.Sanitizers;

public class SAMLFeedbackException extends org.opensaml.saml.common.SAMLException {
	private static final long serialVersionUID = 1L;
	private String feedbackMessage = "";

	public SAMLFeedbackException( String message ) {
		super(message);
		this.feedbackMessage = sanitize(message);
	}

	public SAMLFeedbackException( String message, Exception e ) {
		super(message, e);
		this.feedbackMessage = sanitize(message);
	}

	public SAMLFeedbackException( Exception e ) {
		super(e);
		this.feedbackMessage = sanitize(e.getMessage());
	}

	public SAMLFeedbackException addFeedbackMessage( String feedback ) {
		this.feedbackMessage = sanitize(feedback);
		return this;
	}

	public String getFeedbackMessage() {
		return this.feedbackMessage;
	}
	
	public String sanitize(String input) {
		return Sanitizers.FORMATTING.sanitize(input);
	}
	
}