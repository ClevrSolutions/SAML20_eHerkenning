package saml20.implementation.wrapper;

import com.google.common.collect.ImmutableList;
import com.mendix.core.Core;
import com.mendix.logging.ILogNode;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.encryption.support.ChainingEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import saml20.implementation.common.Constants;
import saml20.implementation.common.SAMLUtil;

public class MxSAMLEncryptedAssertion extends MxSAMLObject {
	private static final ILogNode _logNode = Core.getLogger(Constants.LOGNODE);

	private final EncryptedAssertion encrypted;

	public MxSAMLEncryptedAssertion( EncryptedAssertion assertion ) {
		super(assertion);
		this.encrypted = assertion;
		if ( assertion.getEncryptedData().getType() == null ) {
			assertion.getEncryptedData().setType("http://www.w3.org/2001/04/xmlenc#Element");
		}
	}

	public static MxSAMLAssertion decryptAssertion( Response response, Credential credential, boolean allowUnencrypted ) throws SAMLException {
		if ( response.getEncryptedAssertions().size() > 0 ) {
			MxSAMLEncryptedAssertion encryptedAssertion = new MxSAMLEncryptedAssertion(response.getEncryptedAssertions().get(0));

			return encryptedAssertion.decryptAssertion(credential);
		}
		else {
			if ( !allowUnencrypted && !response.getAssertions().isEmpty() ) {
				throw new SAMLException("Assertion is not encrypted");
			}
		}

		return null;
	}

	private MxSAMLAssertion decryptAssertion( Credential credential ) throws SAMLException {
		KeyInfoCredentialResolver keyResolver = new StaticKeyInfoCredentialResolver(credential);

		ChainingEncryptedKeyResolver kekResolver = new ChainingEncryptedKeyResolver(ImmutableList.of(
				new InlineEncryptedKeyResolver(), new EncryptedElementTypeEncryptedKeyResolver(), new SimpleRetrievalMethodEncryptedKeyResolver()
		));

		try {
			if ( _logNode.isDebugEnabled() )
				_logNode.debug("Assertion encrypted: " + this.encrypted);

			Decrypter decrypter = new Decrypter(null, keyResolver, kekResolver);

			// due to a bug in OpenSAML, we have to convert the assertion to and from xml
			// otherwise the signature will not validate later on
			Assertion assertion = decrypter.decrypt(this.encrypted);
			MxSAMLAssertion res = new MxSAMLAssertion(assertion);
			assertion = (Assertion) SAMLUtil.unmarshallElementFromString(res.toXML());

			if ( _logNode.isDebugEnabled() )
				_logNode.debug("Decrypted assertion: " + res.toXML());

			return new MxSAMLAssertion(assertion);
		}
		catch( DecryptionException e ) {
			throw new SAMLException(e);
		}
	}

}
