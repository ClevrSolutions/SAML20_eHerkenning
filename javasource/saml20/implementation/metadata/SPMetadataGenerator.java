package saml20.implementation.metadata;

import java.io.ByteArrayOutputStream;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.util.UUID;

import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.security.x509.BasicX509Credential;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.mendix.core.Core;
import com.mendix.logging.ILogNode;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IMendixObject;

import eherkenning.implementation.OpenSAMLUtils;
import saml20.implementation.common.Constants;
import saml20.implementation.security.CredentialRepository;
import saml20.proxies.SPMetadata;

public class SPMetadataGenerator {

	private static final ILogNode _logNode = Core.getLogger(Constants.LOGNODE);

	public static ByteArrayOutputStream generate( IContext context, IMendixObject spMetadataConfiguration, CredentialRepository credentialRepository ) throws SAMLException {
		try {
			SPMetadata spMetadataConfigurationObject = SPMetadata.initialize(context, spMetadataConfiguration);
			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

			String applicationRootURL = Constants._getInstance().getSP_URI();
			String entityId = spMetadataConfigurationObject.getEntityID();

			// check if SSOConfigurationObject is available, should be as it is created in
			// StartSAML.java;
			if ( spMetadataConfigurationObject.equals(null) )
				throw new SAMLException("SSO Configuration is not available");

			// check if entity ID is specified
			if ( spMetadataConfigurationObject.getEntityID() == null || spMetadataConfigurationObject.getEntityID().isEmpty() ) {
				entityId = applicationRootURL;
				spMetadataConfigurationObject.setEntityID(applicationRootURL);
			}

			// root elements
			Document doc = docBuilder.newDocument();

			Element entityDescriptor = doc.createElement("md:EntityDescriptor");
			entityDescriptor.setAttribute("ID", "_" + UUID.randomUUID().toString()); // CUSTOM
			entityDescriptor.setAttribute("entityID", entityId);
			entityDescriptor.setAttribute("cacheDuration", "P3Y");
			entityDescriptor.setAttribute("xmlns:md", SAMLConstants.SAML20MD_NS);
			entityDescriptor.setAttribute("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance"); // CUSTOM
			entityDescriptor.setAttribute("xmlns:xs", "http://www.w3.org/2001/XMLSchema"); // CUSTOM
			entityDescriptor.setAttribute("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion"); // CUSTOM
			doc.appendChild(entityDescriptor);

			if ( !applicationRootURL.endsWith("/") ) {
				applicationRootURL += "/";
			}

			// SPSSODescriptor
			Element spssoDescriptor = doc.createElement("md:SPSSODescriptor");
			spssoDescriptor.setAttribute("protocolSupportEnumeration", Constants.PROTOCOL);
			// If encryption / signing enabled, indicate this in the metadata
			// See SAML metadata standard, par 2.4.4 Element <SPSSODescriptor>
			if (spMetadataConfigurationObject.getUseEncryption()) {
				spssoDescriptor.setAttribute("AuthnRequestsSigned", "true");
				spssoDescriptor.setAttribute("WantAssertionsSigned", "true");
			}
			entityDescriptor.appendChild(spssoDescriptor);

			BasicX509Credential cert = credentialRepository.getCredential(Constants.CERTIFICATE_PASSWORD, entityId);

			try {
				if ( cert != null ) {
					// KeyDescriptor + Certificate information
					Element keyDescriptor = doc.createElement("md:KeyDescriptor");

					keyDescriptor.setAttribute("use", "signing"); // CUSTOM
					Element keyInfo = doc.createElement("ds:KeyInfo");
					keyInfo.setAttribute("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#");
					Element keyName = doc.createElement("ds:KeyName"); // CUSTOM
					keyName.setTextContent(UUID.randomUUID().toString()); // CUSTOM
					keyInfo.appendChild(keyName); // CUSTOM
					keyDescriptor.appendChild(keyInfo);

					Element X509Data = doc.createElement("ds:X509Data");
					keyInfo.appendChild(X509Data);					

					Element X509Certificate = doc.createElement("ds:X509Certificate");

					X509Certificate.setTextContent(Base64.getEncoder().encodeToString(cert.getEntityCertificate().getEncoded()));

					X509Data.appendChild(X509Certificate);

					spssoDescriptor.appendChild(keyDescriptor);
					
					// CUSTOM START key for encryption
					Element keyDescriptor2 = doc.createElement("md:KeyDescriptor");
					keyDescriptor2.setAttribute("use", "encryption");
					Element keyInfo2 = doc.createElement("ds:KeyInfo");
					keyInfo2.setAttribute("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#");
					Element keyName2 = doc.createElement("ds:KeyName");
					keyName2.setTextContent(UUID.randomUUID().toString());
					keyInfo2.appendChild(keyName2);
					keyDescriptor2.appendChild(keyInfo2);
					Element X509Data2 = doc.createElement("ds:X509Data");
					keyInfo2.appendChild(X509Data2);
					Element X509Certificate2 = doc.createElement("ds:X509Certificate");
					X509Certificate2.setTextContent(Base64.getEncoder().encodeToString(cert.getEntityCertificate().getEncoded()));
					X509Data2.appendChild(X509Certificate2);
					spssoDescriptor.appendChild(keyDescriptor2);
					// CUSTOM END
				}
			}
			catch( CertificateEncodingException | DOMException e ) {
				_logNode.error("Unable to use certificate");
			}

			// LogoutService
			Element logoutService2 = doc.createElement("md:SingleLogoutService");
			logoutService2.setAttribute("Location", applicationRootURL + Constants._getInstance().SSO_LOGOUT_PATH);
			logoutService2.setAttribute("Binding", SAMLConstants.SAML2_REDIRECT_BINDING_URI);
			spssoDescriptor.appendChild(logoutService2);

			Element logoutService3 = doc.createElement("md:SingleLogoutService");
			logoutService3.setAttribute("Location", applicationRootURL + Constants._getInstance().SSO_LOGOUT_PATH);
			logoutService3.setAttribute("Binding", SAMLConstants.SAML2_POST_BINDING_URI);
			spssoDescriptor.appendChild(logoutService3);

			// ACS
			Element acs1 = doc.createElement("md:AssertionConsumerService");
			acs1.setAttribute("Location", applicationRootURL + Constants._getInstance().SSO_ASSERTION_PATH);
			acs1.setAttribute("index", "1");
			acs1.setAttribute("Binding", SAMLConstants.SAML2_POST_BINDING_URI);
			acs1.setAttribute("isDefault", "true"); // CUSTOM
			spssoDescriptor.appendChild(acs1);

			Element acs2 = doc.createElement("md:AssertionConsumerService");
			acs2.setAttribute("Location", applicationRootURL + Constants._getInstance().SSO_ASSERTION_PATH);
			acs2.setAttribute("index", "2");
			acs2.setAttribute("Binding", SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
			spssoDescriptor.appendChild(acs2);

			// CUSTOM AttributeConsumingService
			Element atcs = doc.createElement("md:AttributeConsumingService");
			atcs.setAttribute("index", "0");
			atcs.setAttribute("isDefault", "true");
			Element sn = doc.createElement("md:ServiceName");
			sn.setAttribute("xml:lang", "nl-NL");
			sn.setTextContent("MijnNZa");
			atcs.appendChild(sn);
			Element ra = doc.createElement("md:RequestedAttribute");
			ra.setAttribute("Name", "urn:nl-eid-gdi:1.0:ServiceUUID");
			Element av = doc.createElement("saml:AttributeValue");
			av.setAttribute("xsi:type", "xs:string");
			av.setTextContent("51444853-3657-4754-574c-434e36484e4e");
			ra.appendChild(av);
			atcs.appendChild(ra);
			spssoDescriptor.appendChild(atcs);
			// CUSTOM END
			// Organization
			Element organization = doc.createElement("md:Organization");
			entityDescriptor.appendChild(organization);

			Element organizationName = doc.createElement("md:OrganizationName");
			organizationName.appendChild(doc.createTextNode(spMetadataConfigurationObject.getOrganizationName()));
			organizationName.setAttribute("xml:lang", "en");
			organization.appendChild(organizationName);

			Element organizationDisplayName = doc.createElement("md:OrganizationDisplayName");
			organizationDisplayName.appendChild(doc.createTextNode(spMetadataConfigurationObject.getOrganizationDisplayName()));
			organizationDisplayName.setAttribute("xml:lang", "en");
			organization.appendChild(organizationDisplayName);

			Element organizationURL = doc.createElement("md:OrganizationURL");
			organizationURL.appendChild(doc.createTextNode(spMetadataConfigurationObject.getOrganizationURL()));
			organizationURL.setAttribute("xml:lang", "en");
			organization.appendChild(organizationURL);

			// Contact
			Element contact = doc.createElement("md:ContactPerson");
			contact.setAttribute("contactType", "administrative");
			entityDescriptor.appendChild(contact);

			if ( spMetadataConfigurationObject.getContactGivenName() != null && !"".equals(spMetadataConfigurationObject.getContactGivenName()) ) {
				Element givenName = doc.createElement("md:GivenName");
				givenName.appendChild(doc.createTextNode(spMetadataConfigurationObject.getContactGivenName()));
				contact.appendChild(givenName);
			}

			if ( spMetadataConfigurationObject.getContactSurName() != null && !"".equals(spMetadataConfigurationObject.getContactSurName()) ) {
				Element surName = doc.createElement("md:SurName");
				surName.appendChild(doc.createTextNode(spMetadataConfigurationObject.getContactSurName()));
				contact.appendChild(surName);
			}

			if ( spMetadataConfigurationObject.getContactEmailAddress() != null && !"".equals(spMetadataConfigurationObject.getContactEmailAddress()) ) {
				Element emailaddress = doc.createElement("md:EmailAddress");
				emailaddress.appendChild(doc.createTextNode(spMetadataConfigurationObject.getContactEmailAddress()));
				contact.appendChild(emailaddress);
			}

			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			Transformer transformer = transformerFactory.newTransformer();
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			
			doc = OpenSAMLUtils.addSign(doc, cert.getPrivateKey(), cert.getEntityCertificate(), "", ""); // Custom	
			DOMSource source = new DOMSource(doc);

			ByteArrayOutputStream out = new ByteArrayOutputStream();

			StreamResult result = new StreamResult(out);

			transformer.transform(source, result);

			return out;
		}
		catch( TransformerException | ParserConfigurationException e ) {
			throw new SAMLException("Unable to generate SP Metadata file.", e);
		}
	}

}
