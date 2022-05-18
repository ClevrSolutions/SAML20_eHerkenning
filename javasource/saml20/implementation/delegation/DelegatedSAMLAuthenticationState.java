/**
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a
 * copy of the License at:
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package saml20.implementation.delegation;

import com.mendix.core.Core;
import org.apache.xerces.parsers.DOMParser;
import org.opensaml.saml.common.SAMLException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import saml20.implementation.common.Constants;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class DelegatedSAMLAuthenticationState {

    // SOAP request from the WSP
    private byte[] soapRequest = null;

    // DOM of the SOAP request to manipulate
    private Document soapRequestDom = null;

    // URL where to send the SOAP response, or AuthnRequest response
    private String responseConsumerURL = null;

    // PAOS MessageID
    private String paosMessageID = null;

    // RelayState element to use for passing the SOAP Response, or AuthnRequest
    // response, back to the WSP
    private Element relayStateElement = null;

    // The modified SOAP Request for sending to the IdP
    private String modifiedSOAPRequest = null;

    // SOAP response from the IdP
    private String soapResponse = null;

    // Modified SOAP response for sending back to the SP
    private String modifiedSOAPResponse = null;

    private String idpLocation = null;


    /**
     * This method is intentionally package-scoped to maintain access to other classed from this package, but to keep it
     * from the public API documentation.
     */
    public byte[] getSoapRequest() {
        return this.soapRequest;
    }

    /**
     * This method is intentionally package-scoped to maintain access to other classed from this package, but to keep it
     * from the public API documentation.
     */
    public void setSoapRequest(byte[] soapRequest) {
        this.soapRequest = soapRequest;
    }

    /**
     * This method is intentionally package-scoped to maintain access to other classed from this package, but to keep it
     * from the public API documentation.
     * @throws SAMLException
     */
    public Document getSoapRequestDom() throws SAMLException {

        if (this.soapRequestDom == null && this.soapRequest != null) {
            try (ByteArrayInputStream is = new ByteArrayInputStream(this.getSoapRequest())) {
                InputSource source = new InputSource(is);
                DOMParser parser = new DOMParser();
                parser.setFeature("http://xml.org/sax/features/namespaces", true);
                parser.parse(source);
                this.soapRequestDom = parser.getDocument();
            } catch (SAXException | IOException ex) {
                Core.getLogger(Constants.LOGNODE).error("Error when parsing the response as XML, the response was: " + new String(this.getSoapRequest()), ex);
                throw new SAMLException("Error when parsing the response as XML.", ex);
            }
        }

        return this.soapRequestDom;
    }

    public void setIdPEndpointLocation(String location) {
        this.idpLocation = location;
    }

    public String getIdpLocation() {
        return this.idpLocation;
    }

    /**
     * This method is intentionally package-scoped to maintain access to other classed from this package, but to keep it
     * from the public API documentation.
     */
    public void setSoapRequestDom(Document soapRequestDom) {
        this.soapRequestDom = soapRequestDom;
    }

    /**
     * This method is intentionally package-scoped to maintain access to other classed from this package, but to keep it
     * from the public API documentation.
     */
    public String getResponseConsumerURL() {
        return this.responseConsumerURL;
    }

    /**
     * This method is intentionally package-scoped to maintain access to other classed from this package, but to keep it
     * from the public API documentation.
     */
    public void setResponseConsumerURL(String responseConsumerURL) {
        this.responseConsumerURL = responseConsumerURL;
    }

    /**
     * This method is intentionally package-scoped to maintain access to other classed from this package, but to keep it
     * from the public API documentation.
     */
    public String getPaosMessageID() {
        return this.paosMessageID;
    }

    /**
     * This method is intentionally package-scoped to maintain access to other classed from this package, but to keep it
     * from the public API documentation.
     */
    public void setPaosMessageID(String paosMessageID) {
        this.paosMessageID = paosMessageID;
    }

    /**
     * This method is intentionally package-scoped to maintain access to other classed from this package, but to keep it
     * from the public API documentation.
     */
    public Element getRelayStateElement() {
        return this.relayStateElement;
    }

    /**
     * This method is intentionally package-scoped to maintain access to other classed from this package, but to keep it
     * from the public API documentation.
     */
    public void setRelayStateElement(Element relayStateElement) {
        this.relayStateElement = relayStateElement;
    }

    /**
     * This method is intentionally package-scoped to maintain access to other classed from this package, but to keep it
     * from the public API documentation.
     */
    public String getModifiedSOAPRequest() {
        return this.modifiedSOAPRequest;
    }

    /**
     * This method is intentionally package-scoped to maintain access to other classed from this package, but to keep it
     * from the public API documentation.
     */
    public void setModifiedSOAPRequest(String modifiedSOAPRequest) {
        this.modifiedSOAPRequest = modifiedSOAPRequest;
    }

    /**
     * This method is intentionally package-scoped to maintain access to other classed from this package, but to keep it
     * from the public API documentation.
     */
    public String getSoapResponse() {
        return this.soapResponse;
    }

    /**
     * This method is intentionally package-scoped to maintain access to other classed from this package, but to keep it
     * from the public API documentation.
     */
    public void setSoapResponse(String soapResponse) {
        this.soapResponse = soapResponse;
    }

    /**
     * This method is intentionally package-scoped to maintain access to other classed from this package, but to keep it
     * from the public API documentation.
     */
    public String getModifiedSOAPResponse() {
        return this.modifiedSOAPResponse;
    }

    /**
     * This method is intentionally package-scoped to maintain access to other classed from this package, but to keep it
     * from the public API documentation.
     */
    public void setModifiedSOAPResponse(String modifiedSOAPResponse) {
        this.modifiedSOAPResponse = modifiedSOAPResponse;
    }
}
