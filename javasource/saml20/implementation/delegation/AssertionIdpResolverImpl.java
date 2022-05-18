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

import org.opensaml.saml.common.SAMLException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import saml20.implementation.wrapper.MxSAMLAssertion;

import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;

/**
 * This class provides IdP ECP endpoint resolution based on the endpoint
 * reference (EPR) provided by Shibboleth IdP in the assertion.
 *
 * @author Adam Rybicki
 */
public class AssertionIdpResolverImpl  {
    private final XPathExpressionExecutor xPathExpressionPool;
    
    public AssertionIdpResolverImpl(XPathExpressionExecutor xPathExpressionPool) {
        this.xPathExpressionPool = xPathExpressionPool;
    }

    /* (non-Javadoc)
     * @see edu.uchicago.portal.portlets.samltest.domain.IdPEPRResolver#resolve(edu.uchicago.portal.portlets.samltest.domain.SAMLSession)
     */
    public void resolve(final Document doc, MxSAMLAssertion assertion, DelegatedSAMLAuthenticationState authnState) throws SAMLException {
        /*
         *  This implementation will extract the EPR from the assertion per the
         *  following instructions from Scott Cantor.
         *  
         *  Find a <saml:AttributeStatement> and a <saml:Attribute> with the Name of
         *  "urn:liberty:ssos:2006-08".
         *  
         *  Verify the <disco:ServiceType> matches that URI as well.
         *  
         *  Verify the <disco:ProviderID> matches the expected IdP's entityID.
         *  
         *  Verify the <sbf:Framework> version is at least 2.0.
         *  
         *  The location to use will be in the <wsa:Address> element.
         *  
         *  Iterate over the <disco:SecurityContext> elements to find a context
         *  compatible with the client. This means finding a <disco:SecurityMechID> with
         *  an acceptable security mechanism, and that it either requires no security
         *  token (unlikely) or that the <sec:Token> has the appropriate usage attribute
         *  and references the enclosing assertion's ID.
         */
        String expression = "/saml2:Assertion/saml2:AttributeStatement/saml2:Attribute[@Name='urn:liberty:ssos:2006-08']";

        try {

            final Node attributeNode = this.xPathExpressionPool.evaluate(expression, doc, XPathConstants.NODE);
            if (attributeNode == null) {
                throw new SAMLException("No saml2:Attribute containing IdP Endpoint Reference found in the SAML assertion.");
            }
            
            expression = "./saml2:AttributeValue/wsa:EndpointReference/wsa:Metadata[disco:ServiceType='urn:liberty:ssos:2006-08']";
            final Node serviceTypeNode = this.xPathExpressionPool.evaluate(expression, attributeNode, XPathConstants.NODE);
            if (serviceTypeNode == null) {
                throw new SAMLException("No matching ServiceType URI found in the Endpoint Reference");
            }

            expression = "./saml2:AttributeValue/wsa:EndpointReference/wsa:Metadata[disco:ProviderID='" + assertion.getIssuer() + "']";
            final Node providerIDNode = this.xPathExpressionPool.evaluate(expression, attributeNode, XPathConstants.NODE);
            if (providerIDNode == null) {
                throw new SAMLException("Provider ID in the Endpoint Reference does not match the IdP previously established");
            }

            expression = "./saml2:AttributeValue/wsa:EndpointReference/wsa:Metadata/sbf:Framework[@version>=2.0]";
            final Node frameworkNode = this.xPathExpressionPool.evaluate(expression, attributeNode, XPathConstants.NODE);
            if (frameworkNode == null) {
                throw new SAMLException("Framework version must be at least 2.0");
            }

            expression = "./saml2:AttributeValue/wsa:EndpointReference/wsa:Address";
            final Node addressNode = this.xPathExpressionPool.evaluate(expression, attributeNode, XPathConstants.NODE);
            if (addressNode == null) {
                throw new SAMLException("Endpoint Reference Address node not present");
            }

            final String ep = addressNode.getTextContent();
            authnState.setIdPEndpointLocation(ep);
        }
        catch (XPathExpressionException ex) {
            throw new SAMLException("XPath processing error with expression:" + expression, ex);
        }
    }

}
