/**
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a
 * copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package saml20.implementation.delegation;

import javax.xml.XMLConstants;
import javax.xml.namespace.NamespaceContext;
import java.util.*;

/**
 * This class is needed for resolving the XML namespace prefixes used during
 * delegated SAML authentication
 *  
 * @author Adam Rybicki
 */
public class SAMLNamespaceContext implements NamespaceContext {
    private static final String[] PREFIXES = {
        "saml2", 
        "ds", 
        "S", 
        "soap", 
        "env", 
        "paos", 
        "ecp", 
        "samlp", 
        "wsa", 
        "sbf",
        "sb", 
        "disco", };

    private static final String[] URIS = { 
        "urn:oasis:names:tc:SAML:2.0:assertion",
        "http://www.w3.org/2000/09/xmldsig#", 
        "http://schemas.xmlsoap.org/soap/envelope/",
        "http://schemas.xmlsoap.org/soap/envelope/", 
        "http://www.w3.org/2003/05/soap-envelope",
        "urn:liberty:paos:2003-08", 
        "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp",
        "urn:oasis:names:tc:SAML:2.0:protocol", 
        "http://www.w3.org/2005/08/addressing", 
        "urn:liberty:sb",
        "urn:liberty:sb:2006-08", 
        "urn:liberty:disco:2006-08", };

    private static final Map<String, String> PREFIX_TO_URI = new LinkedHashMap<String, String>(PREFIXES.length);
    private static final Map<String, String> URI_TO_PREFIX = new LinkedHashMap<String, String>(PREFIXES.length);

    static {
        for (int i = 0; i < PREFIXES.length; i++) {
            PREFIX_TO_URI.put(PREFIXES[i], URIS[i]);
            URI_TO_PREFIX.put(URIS[i], PREFIXES[i]);
        }
    }

    @Override
	public String getNamespaceURI(String prefix) {
        if (prefix == null) {
            throw new IllegalArgumentException();
        }
        
        if (XMLConstants.DEFAULT_NS_PREFIX.equals(prefix)) {
            return XMLConstants.NULL_NS_URI;
        }
        else if (XMLConstants.XML_NS_PREFIX.equals(prefix)) {
            return XMLConstants.XML_NS_URI;
        }
        else if (XMLConstants.XMLNS_ATTRIBUTE.equals(prefix)) {
            return XMLConstants.XMLNS_ATTRIBUTE_NS_URI;
        }
        
        final String uri = PREFIX_TO_URI.get(prefix);
        if (uri != null) {
            return uri;
        }

        return XMLConstants.NULL_NS_URI;
    }

    @Override
	public String getPrefix(String uri) {
        if (uri == null) {
            throw new IllegalArgumentException();
        }
        
        if (XMLConstants.NULL_NS_URI.equals(uri)) {
            return XMLConstants.DEFAULT_NS_PREFIX;
        }
        else if (XMLConstants.XML_NS_URI.equals(uri)) {
            return XMLConstants.XML_NS_PREFIX;
        }
        else if (XMLConstants.XMLNS_ATTRIBUTE_NS_URI.equals(uri)) {
            return XMLConstants.XMLNS_ATTRIBUTE;
        }
        
        return URI_TO_PREFIX.get(uri);
    }

    @Override
	public Iterator<String> getPrefixes(String uri) {
        final String prefix = this.getPrefix(uri);
        if (prefix == null) {
            final Set<String> s = Collections.emptySet();
            return s.iterator();
        }
        
        return Collections.singleton(prefix).iterator();
    }
}
