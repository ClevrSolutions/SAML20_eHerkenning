package saml20.implementation.common;

import com.mendix.core.Core;
import com.mendix.core.CoreException;
import com.mendix.logging.ILogNode;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IMendixIdentifier;
import com.mendix.systemwideinterfaces.core.IMendixObject;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.opensaml.core.xml.ElementExtensibleXMLObject;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import saml20.implementation.SAMLFeedbackException;
import saml20.implementation.SAMLRequestContext;
import saml20.implementation.wrapper.MxSAMLObject;
import saml20.proxies.*;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class SAMLUtil {

    private static final ILogNode _logNode = Core.getLogger(Constants.LOGNODE);

    private static final Map<Class<?>, QName> elementCache = new ConcurrentHashMap<>();

    /**
     * Build a new empty object of the requested type.
     * <p>
     * The requested type must have a DEFAULT_ELEMENT_NAME attribute describing the element type as a QName.
     *
     * @param <T> SAML Object type
     */
    @SuppressWarnings("unchecked")
    public static <T extends XMLObject> T buildXMLObject(Class<T> type) {
        try {
            QName objectQName = getElementQName(type);
            XMLObjectBuilder<T> builder = XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilderOrThrow(objectQName);
            return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(), objectQName.getPrefix());
        } catch (SecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private static <T> QName getElementQName(Class<T> type) {
        if (elementCache.containsKey(type))
            return elementCache.get(type);

        try {
            Field typeField;
            try {
                typeField = type.getDeclaredField("DEFAULT_ELEMENT_NAME");
            } catch (NoSuchFieldException ex) {
                typeField = type.getDeclaredField("ELEMENT_NAME");
            }

            QName objectQName = (QName) typeField.get(null);
            elementCache.put(type, objectQName);
            return objectQName;
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Unmarshall a string containing a SAML2.0 document in XML to an XMLObject.
     *
     * @param elementString The XML object as a string
     * @return The corresponding {@link XMLObject}
     * @throws SAMLException
     */
    public static XMLObject unmarshallElementFromString(String elementString) throws SAMLException {
        try {
            Element samlElement = loadElementFromString(elementString);

            return XMLObjectSupport.getUnmarshaller(samlElement).unmarshall(samlElement);
        } catch (UnmarshallingException e) {
            _logNode.error("Unmarshalling failed when parsing element string " + elementString, e);
            throw new SAMLException(e);
        }
    }

    public static XMLObject unmarshallElementFromFile(String fileName) throws SAMLException {
        File file = new File(fileName);
        if (!file.isFile() || !file.canRead()) {
            _logNode.error("Can't find or read file " + fileName);
            throw new RuntimeException("Cannot find file " + fileName);
        }

        try {
            Element samlElement = loadElementFromFile(fileName);

            // TODO: jeroen review this
            _logNode.debug("Stripping comments from SAML...");

            removeRecursively(samlElement, Node.COMMENT_NODE, null);

            samlElement.normalize();

            final Unmarshaller unmarshaller = XMLObjectSupport.getUnmarshaller(samlElement);
            return unmarshaller.unmarshall(samlElement);
        } catch (UnmarshallingException e) {
            throw new SAMLException(e);
        }
    }

    private static void removeRecursively(Node node, short nodeType, String name) {
        if (node.getNodeType() == nodeType && (name == null || node.getNodeName().equals(name))) {
            node.getParentNode().removeChild(node);
        } else {
            // check the children recursively
            NodeList list = node.getChildNodes();
            for (int i = 0; i < list.getLength(); i++) {
                removeRecursively(list.item(i), nodeType, name);
            }
        }
    }

    private static Element loadElementFromFile(String fileName) throws SAMLException {
        try (BufferedReader reader = new BufferedReader(new FileReader(fileName))) {
            StringBuilder sb = new StringBuilder(2048);

            char[] chars = new char[1024];
            int numRead;
            while ((numRead = reader.read(chars)) != -1) {
                String readData = String.valueOf(chars, 0, numRead);
                sb.append(readData);
                chars = new char[1024];
            }
            if (_logNode.isDebugEnabled())
                _logNode.debug(sb.toString());

            return loadElementFromString(sb.toString());
        } catch (IOException e) {
            throw new SAMLException(e);
        }
    }

    /**
     * Parse an XML string.
     *
     * @param elementString The String to parse
     * @return The corresponding document {@link Element}.
     * @throws SAMLException
     */
    private static Element loadElementFromString(String elementString) throws SAMLException {
        try {
            DocumentBuilderFactory newFactory = getDocumentBuilderFactory();
            newFactory.setNamespaceAware(true);

            DocumentBuilder builder = newFactory.newDocumentBuilder();
            Document doc;
            try (ByteArrayInputStream inputStream = new ByteArrayInputStream(elementString.getBytes(StandardCharsets.UTF_8))) {
                doc = builder.parse(inputStream);
            }

            return doc.getDocumentElement();
        } catch (ParserConfigurationException | IOException | SAXException e) {
            _logNode.error("Unable to parse element string " + elementString, e);
            throw new SAMLException(e);
        }
    }

    private static DocumentBuilderFactory getDocumentBuilderFactory() throws ParserConfigurationException {
        DocumentBuilderFactory newFactory = DocumentBuilderFactory.newInstance();
        newFactory.setNamespaceAware(true);

        // disallow external doctype decl to prevent XXE attacks -- https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet
        newFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        newFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        newFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

        return newFactory;
    }

    public static Issuer createIssuer(String value) {
        if (value == null)
            return null;

        Issuer issuer = buildXMLObject(Issuer.class);
        issuer.setValue(value);
        return issuer;
    }

    /**
     * Pretty print an XML object.
     *
     * @param object The SAML object
     * @return A SAML object as pretty print XML
     * @throws SAMLException
     */
    public static String getSAMLObjectAsPrettyPrintXML(XMLObject object) throws SAMLException {
        if (object == null) {
            throw new IllegalArgumentException("Object cannot be null");
        }
        Element e1 = marshallObject(object);
        return SerializeSupport.prettyPrintXML(e1);
    }

    public static Element marshallObject(XMLObject object) throws SAMLException {
        try {
            return XMLObjectSupport.marshall(object);
        } catch (MarshallingException e) {
            throw new SAMLException(e);
        }
//        if (object.getDOM() == null) {
//            Marshaller m = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
//            if (m == null) {
//                throw new IllegalArgumentException("No unmarshaller for " + object);
//            }
//            try {
//                return m.marshall(object);
//            } catch (MarshallingException e) {
//                throw new SAMLException(e);
//            }
//        } else {
//            return object.getDOM();
//        }
    }

    /**
     * Get the first element of a specific type from a parent element.
     *
     * @param obj  The parent element. If this is <code>null</code>, <code>null</code> is returned.
     * @param type The type to retrieve.
     * @return The first element, or <code>null</code> if no elements were found.
     */
    @SuppressWarnings("unchecked")
    public static <T extends XMLObject> T getFirstElement(ElementExtensibleXMLObject obj, Class<T> type) {
        if (obj == null)
            return null;

        for (XMLObject o : obj.getUnknownXMLObjects()) {
            if (type.isInstance(o)) {
                return (T) o;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    /**
     * Clone a XML object, including all references.
     */
    public static <T extends XMLObject> T clone(T object) throws SAMLException {
        try {
            return XMLObjectSupport.cloneXMLObject(object);
        } catch (MarshallingException | UnmarshallingException e) {
            throw new SAMLException(e);
        }
    }

    public static List<IMendixObject> getActiveSSOConfig(IContext context) {
        /*
         * Retrieve the active SSOConfiguration with the given context, this allows us to use the context from the
         * microflow. We need to use the MF context in order to get the new active SSO Config object
         */
        List<IMendixObject> list = MendixUtils.retrieveFromDatabase(context, "//%s[%s = true()]", null,
                SSOConfiguration.getType(),
                SSOConfiguration.MemberNames.Active.toString()
        );

        if (list.size() >= 1) {
            return list;
        }

        return null;
    }

    public static IMendixObject getMetadataConfig(IContext context) throws SAMLFeedbackException {
        List<IMendixObject> list = MendixUtils.retrieveFromDatabase(context, "//%s", null, SPMetadata.getType());

        if (list.size() == 1) {
            IMendixObject spmetadata = list.get(0);

            String sp_consumerUrl = spmetadata.getValue(context, SPMetadata.MemberNames.ApplicationURL.toString());
            if (sp_consumerUrl == null) {
                try {
                    sp_consumerUrl = Constants._getInstance().getSP_URI();

                    spmetadata.setValue(context, SPMetadata.MemberNames.ApplicationURL.toString(), sp_consumerUrl);
                    // Commit in the given context to prevent any possible deadlocks
                    Core.commit(context, spmetadata);
                } catch (CoreException e) {
                    _logNode.error("Unable to update the SP Metadata with the Correct Application URL");
                }
            }

            list.clear();
            return spmetadata;
        }

        throw new SAMLFeedbackException("Unable to initialize the SSO configuration since the SP Metadata cannot be found");
    }

    public static String stacktraceToString(Exception ex) {
        return ExceptionUtils.getFullStackTrace(ex);

    }

    public static void logSAMLRequestMessage(SAMLRequestContext context, String randomId, MxSAMLObject mxSAMLObject, IMendixObject ssoConfiguration) throws SAMLException {
        SSOConfiguration ssoconfig = SSOConfiguration.initialize(context.getIContext(), ssoConfiguration);
        SAMLRequest newFileDocument = SAMLRequest.initialize(context.getIContext(), Core.instantiate(context.getIContext(), SAMLRequest.entityName));
        // newFileDocument.setSAMLRequest_Endpoint(context.getContext(), currentEndpoint);
        newFileDocument.setSAMLRequest_SSOConfiguration(context.getIContext(), ssoconfig);
        newFileDocument.setRequestID(randomId);
        newFileDocument.sethasRequest(saml20.proxies.YesNo.Yes);

        try {
            if (ssoconfig.getIsSAMLLoggingEnabled()) {
                String tmpFileName = randomId + ".xml";
                String tmpFilePath = Core.getConfiguration().getTempPath() + File.separator + tmpFileName;

                try (FileWriter fw = new FileWriter(tmpFilePath);
                     BufferedWriter out = new BufferedWriter(fw)) {
                    final String xml = mxSAMLObject.toXML();
                    _logNode.debug("Writing SAML object " + xml);
                    out.write(xml);
                } catch (IOException e) {
                    _logNode.error("Unable to store the xml information from the AuthnRequest,, " + e.getMessage(), e);
                }

                File newFile = new File(tmpFilePath);
                newFileDocument.setName(tmpFileName);

                try (FileInputStream inputStream = new FileInputStream(newFile)) {
                    Core.storeFileDocumentContent(context.getIContext(), newFileDocument.getMendixObject(), inputStream);
                    newFile.delete();
                } catch (IOException e) {
                    _logNode.error("Unable to store the xml information from the AuthnRequest,, " + e.getMessage(), e);
                }
            }
            newFileDocument.commit();
        } catch (CoreException e) {
            throw new SAMLException("Unable to store the SAML AuthnRequest debug info", e);
        }
    }

    public static void logSAMLResponseMessage(SAMLRequestContext context, SAMLRequest samlrequest, StatusResponseType
            logoutResponse, String principal, IMendixObject ssoconfiguration) throws SAMLException {
        String tmpFileName = logoutResponse.getInResponseTo() + ".xml";
        Element element = SAMLUtil.marshallObject(logoutResponse);
        String xml = SerializeSupport.prettyPrintXML(element);
        createSAMLResponseLog(context, samlrequest, xml, tmpFileName, principal, ssoconfiguration);
    }

    private static void createSAMLResponseLog(SAMLRequestContext context, SAMLRequest samlrequest, String
            xml, String tmpFileName, String principal, IMendixObject ssoconfiguration) {
        SSOConfiguration ssoconfig = SSOConfiguration.initialize(context.getIContext(), ssoconfiguration);
        String tmpFile = Core.getConfiguration().getTempPath() + "/inResponseTo" + tmpFileName;
        //In case of unsolicited messages, the ssoconfig can be unknown and thus empty
        if (ssoconfig.getIsSAMLLoggingEnabled()) {
            try (BufferedWriter out = new BufferedWriter(new FileWriter(tmpFile))) {
                out.write(xml);
            } catch (IOException e) {
                _logNode.error("Unable to store samlresponse as filedocument: " + e.getMessage(), e);
            }
        }

        SAMLResponse newFileDocument = null;
        try {
            if (samlrequest == null) {
                samlrequest = new SAMLRequest(context.getIContext());
                samlrequest.setSAMLRequest_SSOConfiguration(context.getIContext(), ssoconfig);
            }
            samlrequest.sethasResponse(YesNo.Yes);
            samlrequest.setReturnedPrincipal(principal);
            samlrequest.commit();

            newFileDocument = new SAMLResponse(context.getIContext());
            newFileDocument.setSAMLResponse_SSOConfiguration(context.getIContext(), ssoconfig);
            newFileDocument.setSAMLRequest_SAMLResponse(samlrequest);

        } catch (CoreException e) {
            _logNode.error("Couldn't create a SAMLResponse fildocument object: " + e.getMessage(), e);
        }

        if (ssoconfig.getIsSAMLLoggingEnabled()) {
            File newFile = new File(tmpFile);
            newFileDocument.setName(tmpFileName);
            try (FileInputStream inputStream = new FileInputStream(newFile)) {
                Core.storeFileDocumentContent(context.getIContext(), newFileDocument.getMendixObject(), inputStream);
            } catch (IOException e) {
                _logNode.error("Unable to store SAMLResponse in filedocument object: " + e.getMessage(), e);
            }
            newFile.delete();
        } else {
            try {
                newFileDocument.commit();
            } catch (CoreException e) {
                _logNode.error("Unable to commit SAMLResponse object: " + e.getMessage(), e);
            }
        }
    }

    public static void createLogLine(String message, SSOLogResult logresult) {
        try {
            _logNode.info(logresult + ": " + message);
            SSOLog newLog = new SSOLog(Core.createSystemContext());
            newLog.setLogonResult(logresult);
            newLog.setMessage(message);
            newLog.commit();
        } catch (CoreException e) {
            _logNode.error("Error creating SSOLog : " + e.getMessage(), e);
        }

    }

    public static SAMLRequest retrieveCorrespondingRequest(IContext context, String inResponseTo) {
        if (inResponseTo == null || inResponseTo.isBlank()) {
            return null;
        }
        try {
            @SuppressWarnings("serial")
            List<IMendixObject> samlrequestList = MendixUtils.retrieveFromDatabase(context, "//%s[%s = $requestId][%s = $no]",
                    new HashMap<String, Object>() {{
                        put("requestId", inResponseTo);
                        put("no", YesNo.No.toString());
                    }},
                    SAMLRequest.entityName,
                    SAMLRequest.MemberNames.RequestID.toString(),
                    SAMLRequest.MemberNames.hasResponse.toString()
            );

            if (samlrequestList.size() == 1)
                return SAMLRequest.initialize(context, samlrequestList.get(0));
            else
                return null;
        } catch (Exception e) {
            return null;
        }
    }

    public static String getEntityIdForConfig(IContext context, IMendixObject ssoConfiguration) {
        IMendixIdentifier edId = ssoConfiguration.getValue(context, SSOConfiguration.MemberNames.SSOConfiguration_PreferedEntityDescriptor.toString());
        if (edId != null) {
            try {
                IMendixObject ed = Core.retrieveId(context, edId);
                return ed.getValue(context, EntityDescriptor.MemberNames.entityID.toString());
            } catch (CoreException e) {
                _logNode.error("Unable to retrieve the entity descriptors");
            }
        }

        return null;
    }

    public static String getRequestIDFromRelayState(String relayState) {
        if (relayState != null && !relayState.equals("")) {
            int first = relayState.indexOf(Constants.RELAYSTATE_SEPARATOR);
            int second = relayState.indexOf(Constants.RELAYSTATE_SEPARATOR, first + 1);
            if (first >= 0) {
                if (second >= 0) {
                    return relayState.substring(first + 1, second);
                } else {
                    return relayState.substring(first + 1);
                }
            }
        }
        return null;
    }

    public static String getContinuationFromRelayState(String relayState) {
        if (relayState != null && !relayState.equals("")) {
            int first = relayState.indexOf(Constants.RELAYSTATE_SEPARATOR);
            int second = relayState.indexOf(Constants.RELAYSTATE_SEPARATOR, first + 1);
            if (first >= 0 && second >= 0) {
                return relayState.substring(second + 1);
            }
        }
        return null;
    }

}