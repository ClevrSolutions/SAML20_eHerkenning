package eherkenning.implementation;

import java.io.StringWriter;
import java.lang.reflect.Field;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import javax.xml.namespace.NamespaceContext;
import javax.xml.namespace.QName;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathFactoryConfigurationException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.XMLUtils;
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
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.google.common.collect.ImmutableList;
import com.mendix.core.Core;
import com.mendix.logging.ILogNode;

import eherkenning.proxies.Enum_ProtocolBinding;
import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
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
	
	public static Integer getAttributeConsumingServiceIndex(SAMLRequestContext context, Metadata metadata) {
		SSOConfiguration config = SSOConfiguration.initialize(context.getIContext(), metadata.getSsoConfiguration());
		Integer index = config.getAttributeConsumingServiceIndex();
        if (index != null && index > 0)
        	return index;
        return 1;
	}
	
	public static Document addSign(Document document, PrivateKey key, X509Certificate certificate) {
		// Based on https://github.com/onelogin/java-saml/blob/master/core/src/main/java/com/onelogin/saml2/util/Util.java#L1406
		
		try {
			String signAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
			String digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";
			String c14nMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
			String tranfromSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
			
			document.normalizeDocument();

			// Signature object
			XMLSignature sig = new XMLSignature(document, null, signAlgorithm, c14nMethod);

			// Including the signature into the document before sign, because
			// this is an envelop signature
			Element root = document.getDocumentElement();
			document.setXmlStandalone(false);

			// If Issuer, locate Signature after Issuer, Otherwise as first child.
			NodeList issuerNodes = query(document, "//saml:Issuer", null);
			Element elemToSign = null;
			if (issuerNodes.getLength() > 0) {
				Node issuer =  issuerNodes.item(0);
				root.insertBefore(sig.getElement(), issuer.getNextSibling());
				elemToSign = (Element) issuer.getParentNode();
			} else {
				NodeList entitiesDescriptorNodes = query(document, "//md:EntitiesDescriptor", null);
				if (entitiesDescriptorNodes.getLength() > 0) {
					elemToSign = (Element)entitiesDescriptorNodes.item(0);
				} else {
					NodeList entityDescriptorNodes = query(document, "//md:EntityDescriptor", null);
					if (entityDescriptorNodes.getLength() > 0) {
						elemToSign = (Element)entityDescriptorNodes.item(0);
					} else {
						elemToSign = root;
					}
				}
				root.insertBefore(sig.getElement(), elemToSign.getFirstChild());
			}

			String id = elemToSign.getAttribute("ID");
			String reference = id;
			if (!id.isEmpty()) {
				elemToSign.setIdAttributeNS(null, "ID", true);
				reference = "#" + id;
			}

			// Create the transform for the document
			Transforms transforms = new Transforms(document);
			transforms.addTransform(tranfromSignature);
			transforms.addTransform(c14nMethod);
			sig.addDocument(reference, transforms, digestAlgorithm);

			// Add the certification info
			sig.addKeyInfo(certificate);

			// Sign the document
			sig.sign(key);			
			
//		try {
//			// Prevent line breaks in XML, cause conflicts.
//			Field f = XMLUtils.class.getDeclaredField("ignoreLineBreaks");
//			f.setAccessible(true);
//			f.set(null, Boolean.TRUE);
//		} catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
			
		} catch (XPathExpressionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (XMLSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		

		return document;
	}
	
	/** 
	 * Prevent issues in SAML signature with unwanted line breaks.
	 * This is a global settings, and might affect other XML generation too.
	 * https://stackoverflow.com/questions/4728300/how-to-produce-xml-signature-with-no-whitespaces-and-line-breaks-in-java
	 * https://crypto.stackexchange.com/questions/61061/signed-xml-signaturevalue-element-value-hash-in-base64-contains-xd
	 */
	public static void ignoreLineBreaksXml() {
		// try {
//			// Prevent line breaks in XML, cause conflicts.
//			Field f = XMLUtils.class.getDeclaredField("ignoreLineBreaks");
//			f.setAccessible(true);
//			f.set(null, Boolean.TRUE);
			System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
			org.apache.xml.security.Init.init();
		// } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
		
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
	}
	
	public static NodeList query(Document dom, String query, Node context) throws XPathExpressionException {
		NodeList nodeList;
		XPath xpath = getXPathFactory().newXPath();
		xpath.setNamespaceContext(new NamespaceContext() {

			@Override
			public String getNamespaceURI(String prefix) {
				String result = null;
				if (prefix.equals("samlp") || prefix.equals("samlp2")) {
					result =  "urn:oasis:names:tc:SAML:2.0:protocol";
				} else if (prefix.equals("saml") || prefix.equals("saml2")) {
					result = "urn:oasis:names:tc:SAML:2.0:assertion";
				} else if (prefix.equals("ds")) {
					result = "http://www.w3.org/2000/09/xmldsig#";
				} else if (prefix.equals("xenc")) {
					result = "http://www.w3.org/2001/04/xmlenc#";
				} else if (prefix.equals("md")) {
					result = "urn:oasis:names:tc:SAML:2.0:metadata";
				}
				return result;
			}

			@Override
			public String getPrefix(String namespaceURI) {
				return null;
			}

			@SuppressWarnings("rawtypes")
			@Override
			public Iterator getPrefixes(String namespaceURI) {
				return null;
			}
		});

		if (context == null) {
			nodeList = (NodeList) xpath.evaluate(query, dom, XPathConstants.NODESET);
		} else {
			nodeList = (NodeList) xpath.evaluate(query, context, XPathConstants.NODESET);
		}
		return nodeList;
	}
	
	private static XPathFactory getXPathFactory() {
		try {
			/*
			 * Since different environments may return a different XPathFactoryImpl, we should try to initialize the factory
			 * using specific implementation that way the XML is parsed in an expected way.
			 *
			 * We should use the standard XPathFactoryImpl that comes standard with Java.
			 *
			 * NOTE: We could implement a check to see if the "javax.xml.xpath.XPathFactory" System property exists and is set
			 *       to a value, if people have issues with using the specified implementor. This would allow users to always
			 *       override the implementation if they so need to.
			 */
			return XPathFactory.newInstance(XPathFactory.DEFAULT_OBJECT_MODEL_URI, "com.sun.org.apache.xpath.internal.jaxp.XPathFactoryImpl", java.lang.ClassLoader.getSystemClassLoader());
		} catch (XPathFactoryConfigurationException e) {
			// LOGGER.debug("Error generating XPathFactory instance: " + e.getMessage(), e);
		}

		/*
		 * If the expected XPathFactory did not exist, we fallback to loading the one defined as the default.
		 *
		 * If this is still throwing an error, the developer can set the "javax.xml.xpath.XPathFactory" system property
		 * to specify the default XPathFactoryImpl implementation to use. For example:
		 *
		 * -Djavax.xml.xpath.XPathFactory:http://java.sun.com/jaxp/xpath/dom=net.sf.saxon.xpath.XPathFactoryImpl
		 * -Djavax.xml.xpath.XPathFactory:http://java.sun.com/jaxp/xpath/dom=com.sun.org.apache.xpath.internal.jaxp.XPathFactoryImpl
		 *
		 */
		return XPathFactory.newInstance();
	}
}
