package eherkenning.implementation;

import java.io.StringWriter;

import javax.xml.namespace.QName;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.EncryptedID;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.impl.EncryptedIDUnmarshaller;
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
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.google.common.collect.ImmutableList;
import com.mendix.core.Core;
import com.mendix.logging.ILogNode;

import eherkenning.proxies.Enum_ProtocolBinding;
import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;
import saml20.implementation.SAMLRequestContext;
import saml20.implementation.common.Constants;
import saml20.implementation.metadata.IdpMetadata.Metadata;
import saml20.proxies.SSOConfiguration;

public class OpenSAMLUtils {
	private static Logger logger = LoggerFactory.getLogger(OpenSAMLUtils.class);
	private static final ILogNode _logNode = Core.getLogger(Constants.LOGNODE);
	private static RandomIdentifierGenerationStrategy secureRandomIdGenerator;

	static {
		secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();
	}

	public static <T> T buildSAMLObject(final Class<T> clazz) {
		T object = null;
		try {
			XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
			QName defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
			object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
		} catch (IllegalAccessException e) {
			throw new IllegalArgumentException("Could not create SAML object");
		} catch (NoSuchFieldException e) {
			throw new IllegalArgumentException("Could not create SAML object");
		}

		return object;
	}

	public static String generateSecureRandomId() {
		return secureRandomIdGenerator.generateIdentifier();
	}

	public static void logSAMLObject(final XMLObject object) {
		Element element = null;

		if (object instanceof SignableSAMLObject && ((SignableSAMLObject) object).isSigned()
				&& object.getDOM() != null) {
			element = object.getDOM();
		} else {
			try {
				Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
				out.marshall(object);
				element = object.getDOM();

			} catch (MarshallingException e) {
				logger.error(e.getMessage(), e);
			}
		}

		try {
			Transformer transformer = TransformerFactory.newInstance().newTransformer();
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			StreamResult result = new StreamResult(new StringWriter());
			DOMSource source = new DOMSource(element);

			transformer.transform(source, result);
			String xmlString = result.getWriter().toString();

			logger.info(xmlString);
			_logNode.info(xmlString);
		} catch (TransformerConfigurationException e) {
			e.printStackTrace();
		} catch (TransformerException e) {
			e.printStackTrace();
		}
	}

	public static NameID getNameIdFromEncryptedID(XMLObject value, Credential credential) {
		KeyInfoCredentialResolver keyResolver = new StaticKeyInfoCredentialResolver(credential);

		ChainingEncryptedKeyResolver kekResolver = new ChainingEncryptedKeyResolver(
				ImmutableList.of(new InlineEncryptedKeyResolver(), new EncryptedElementTypeEncryptedKeyResolver(),
						new SimpleRetrievalMethodEncryptedKeyResolver()));

		Decrypter decrypter = new Decrypter(null, keyResolver, kekResolver);

		NodeList elements = value.getDOM().getElementsByTagNameNS(SAMLConstants.SAML20_NS,
				EncryptedID.DEFAULT_ELEMENT_LOCAL_NAME);
		if (elements.getLength() > 0) {
			_logNode.debug("contains EncryptedID");

			Element element = (Element) elements.item(0);
			if (element != null) {
				// String responsexml = SerializeSupport.prettyPrintXML(element);
				// _logNode.debug("getNameIdFromEncryptedID: " + responsexml);
				EncryptedIDUnmarshaller m = new EncryptedIDUnmarshaller();
				EncryptedID encryptedID;
				try {
					encryptedID = (EncryptedID) m.unmarshall(element);
					NameID decrypted = (NameID) decrypter.decrypt(encryptedID);
					// OpenSAMLUtils.logSAMLObject(decrypted);
					return decrypted;

				} catch (UnmarshallingException e) {
					_logNode.error("UnmarshallingException");
					_logNode.error(e);
					e.printStackTrace();
				} catch (DecryptionException e) {
					_logNode.error("DecryptionException");
					_logNode.error(e);
					e.printStackTrace();
				}
			}
		}

		_logNode.info("No EncryptedID");
		return null;
	}

	public static String getProtocolBinding(SAMLRequestContext context, Metadata metadata) {
		SSOConfiguration config = SSOConfiguration.initialize(context.getIContext(), metadata.getSsoConfiguration());
		if (config.getProtocolBinding() == Enum_ProtocolBinding.ARTIFACT)
			return SAMLConstants.SAML2_ARTIFACT_BINDING_URI;
		return SAMLConstants.SAML2_POST_BINDING_URI;
	}
}
