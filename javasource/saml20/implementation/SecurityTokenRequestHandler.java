package saml20.implementation;

import jakarta.xml.soap.*;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;

public class SecurityTokenRequestHandler {

    String username;
    String password;

    public static void main(String[] args) throws Exception {

        // to add...............
        String to = "[To]";
        String usernameToken = "uuid-----";
        String username = "[Username]";
        String password = "[Password]";
        String applyTo = "[applyTo]";

        final String sPF = "s";
        final String sNS = "http://schemas.xmlsoap.org/soap/envelope";
        final String sQF = sPF + ":";

        final String aPF = "a";
        final String aNS = "http://www.w3.org/2005/08/addressing";
        /* final String aQF = aPF + ":"; */

        final String uPF = "u";
        final String uNS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
        final String uQF = uPF + ":";

        final String oPF = "o";
        final String oNS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        /* final String oQF = oPF + ":"; */

        final String tPF = "trust";
        final String tNS = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
        final String tQF = tPF + ":";

        final String wPF = "wsp";
        final String wNS = "http://schema.xmlsoap.org/ws/2004/09/policy";
        /* final String wQF = wPF + ":"; */

        try {

            // initialize
            SOAPFactory sf = SOAPFactory.newInstance();

            SOAPMessage soapMessage = MessageFactory.newInstance().createMessage();
            SOAPPart soapPart = soapMessage.getSOAPPart();
            SOAPEnvelope soapEnvelope = soapPart.getEnvelope();
            soapEnvelope.removeNamespaceDeclaration("SOAP-ENV");
            soapEnvelope.setPrefix(sPF);

            //line 1-3
            soapEnvelope.addNamespaceDeclaration(sPF, sNS);
            soapEnvelope.addNamespaceDeclaration(aPF, aNS);
            soapEnvelope.addNamespaceDeclaration(uPF, uNS);

            // line 4
            SOAPHeader header = soapEnvelope.getHeader();
            header.setPrefix(sPF);

            // line 5
            SOAPElement hActionElement = header.addChildElement("Action", aPF);
            SOAPElement hActionMUElement = hActionElement.addAttribute(soapEnvelope.createName(sQF + "mustUnderstand"), "1");
            hActionMUElement.setValue("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue");

            // line 6
            SOAPElement hToElement = header.addChildElement("To", aPF);
            SOAPElement hToMUElement = hToElement.addAttribute(soapEnvelope.createName(sQF + "mustUnderstand"), "1");
            hToMUElement.setValue(to);

            // line 7
            SOAPElement hSecurityElement = header.addChildElement(sf.createName("Security", oPF, oNS));
            hSecurityElement.addAttribute(soapEnvelope.createName(sQF + "mustUnderstand"), "1");

            // line 8
            SOAPElement usernameTokenElement = hSecurityElement.addChildElement(soapEnvelope.createName("UsernameToken", oPF, oNS));
            usernameTokenElement.addAttribute(soapEnvelope.createName(uQF + "Id"), usernameToken);

            // line 9
            SOAPElement usernameElement = usernameTokenElement.addChildElement("Username", oPF);
            usernameElement.setValue(username);

            // line 10
            SOAPElement passwordElement = usernameTokenElement.addChildElement("Password", oPF);
            passwordElement.setAttribute("Type", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText");
            passwordElement.setValue(password);

            // line 11-13
            // no code needed (closing tags generated automatically)

            // line 14
            SOAPBody body = soapEnvelope.getBody();
            body.setPrefix(sPF);

            // line 15
            body.addBodyElement(soapEnvelope.createName("RequestSecurityToken", tPF, tNS));

            // line 16
            SOAPBodyElement bAppliesToElement = body.addBodyElement(soapEnvelope.createName("AppliesTo", wPF, wNS));

            // line 17
            SOAPElement endPointReferenceElement = bAppliesToElement.addChildElement("EndPointReference", aPF);

            // line 18
            SOAPElement addressElement = endPointReferenceElement.addChildElement("Address", aPF);
            addressElement.setValue(applyTo);

            // line 19-20
            // no code needed (closing tags generated automatically)           

            // line 21
            SOAPBodyElement bKeyTypeElement = body.addBodyElement(soapEnvelope.createName(tQF + "KeyType"));
            bKeyTypeElement.setValue("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");

            // line 22
            SOAPBodyElement bRequestTypeElement = body.addBodyElement(soapEnvelope.createName(tQF + "RequestType"));
            bRequestTypeElement.setValue("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue");

            // line 23
            SOAPBodyElement bTokenTypeElement = body.addBodyElement(soapEnvelope.createName(tQF + "TokenType"));
            bTokenTypeElement.setValue("urn:oasis:names:tc:SAML:2.0:assertion");

            // line 24-26
            // no code needed (closing tags generated automatically)

            debug_displayResult(soapMessage);

        } catch (Exception e) {
            // Handle This error in the main method that is calling this private method. So just return the Exception as it is...
            throw e;
        }

    }


    public static void connect(SOAPMessage msg) throws SOAPException, IOException {

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        msg.writeTo(out);
        String strMsg = new String(out.toByteArray());

//    	URL url = new URL(request); 
//        HttpURLConnection connection = (HttpURLConnection) url.openConnection();           
//        connection.setDoInput(true); 
//        connection.setInstanceFollowRedirects(false); 
//        connection.setRequestMethod("POST"); 
//        connection.setRequestProperty("Content-Type", "application/soap+xml"); 
//        connection.setRequestProperty("charset", "utf-8");
//        connection.
//        connection.connect();


        String hostname = "www.idp.com";
        int port = 80;
        InetAddress addr = InetAddress.getByName(hostname);

        //Send header
        String path = "/adfs/services/trust/13/UsernameMixed";
        try (Socket sock = new Socket(addr, port);
             OutputStreamWriter streamWriter = new OutputStreamWriter(sock.getOutputStream(), "UTF-8");
             BufferedWriter wr = new BufferedWriter(streamWriter)) {
            // You can use "UTF8" for compatibility with the Microsoft virtual machine.
            wr.write("POST " + path + " HTTP/1.1\r\n");
            wr.write("Connection: Keep-Alive\r\n");
            wr.write("Content-Length: " + strMsg.length() + "\r\n");
            wr.write("Content-Type: application/soap+xml; charset=\"utf-8\"\r\n");
            wr.write("Accept-Encoding: gzip, deflate\r\n");
            wr.write("Content-Type: text/xml; charset=\"utf-8\"\r\n");
            wr.write("Host: " + hostname + "\r\n");
            wr.write("\r\n");

            //Send data
            wr.write(strMsg);

            // Response
            try (InputStreamReader inputStream = new InputStreamReader(sock.getInputStream());
                 BufferedReader rd = new BufferedReader(inputStream)) {
                String line;
                while ((line = rd.readLine()) != null) {
                    System.out.println(line);
                }
            }
        }
    }


    public static void debug_displayResult(SOAPMessage msg) throws SOAPException, IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        msg.writeTo(out);
        String strMsg = new String(out.toByteArray());
        System.out.println(strMsg);
    }

}
