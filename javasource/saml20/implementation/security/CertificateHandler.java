package saml20.implementation.security;

import com.mendix.core.Core;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IMendixObject;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import saml20.proxies.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

public class CertificateHandler {

    private static SimpleDateFormat certDateFormat = new SimpleDateFormat("E MMM dd HH:mm:ss Z yyyy");

    public static void extractCertificateMetaData(IContext context, IMendixObject certObj) throws IOException, CertificateException {
        X509Certificate cert = X509Certificate.initialize(context, certObj);
        InputStream is = Core.getFileDocumentContent(context, certObj);


        //  START OF FIX - "java.io.IOException: DerInputStream.getLength(): lengthTag=127, too big." in Mx Cloud V4 - 2017 May 17th. JPU
        //  this code caused problems in Mx Cloud V4. Amazon S3 based inputstream was cut off after the first few characters.

        /****
         long length = is.available();
         if ( length > Integer.MAX_VALUE ) {
         // File is too large
         }
         byte[] bytes = new byte[(int) length];

         int offset = 0;
         int numRead = 0;
         while( offset < bytes.length && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0 ) {
         offset += numRead;
         }

         if ( offset < bytes.length ) {
         throw new IOException("Could not completely read certificate " + cert.getName());
         }
         *****/

        //	replaced by the following code, which works fine in Cloud V4:

        byte[] bytes = IOUtils.toByteArray(is); // library was already used by the module

        // 	END OF FIX - "java.io.IOException: DerInputStream.getLength(): lengthTag=127, too big." in Mx Cloud V4 - 2017 May 17th. JPU


        is.close();

        String certificateValue = Base64.getEncoder().encodeToString(bytes);

        // Verify the certificate content and extract the basic information such as issuer/subject/etc
        String contents = getCertificateContents(certificateValue);

        String issuer = contents.substring(contents.indexOf("Issuer") + 7, contents.indexOf('\n', contents.indexOf("Issuer"))).trim();
        String subject = contents.substring(contents.indexOf("Subject") + 8, contents.indexOf('\n', contents.indexOf("Subject"))).trim();
        String validfromto = contents.substring(contents.indexOf("Validity: [From: ") + 17, contents.indexOf(']', contents.indexOf("Validity: [From:"))).trim();
        String serialNumber = contents.substring(contents.indexOf("SerialNumber: [") + 17, contents.indexOf(']', contents.indexOf("SerialNumber: ["))).trim();

        String[] datearray = validfromto.split(",");

        Date validfrom = null;
        Date validto = null;
        try {
            validfrom = certDateFormat.parse(datearray[0]);
            validto = certDateFormat.parse(datearray[1].substring(datearray[1].indexOf("To:") + 4));
        } catch (ParseException e) {
        }

        cert.setIssuerName(issuer);
        cert.setSubject(subject);
        cert.setValidFrom(validfrom);
        cert.setValidUntil(validto);
        cert.setSerialNumber(serialNumber);
        cert.setBase64(getBase64Content(context, certObj));

        // TODO do something with a good filename if no name is currently present
        // cert.setName( subject.replace("*","").replace("/","").replace("\\","").replace("=","") + ".crt");
    }

    public static String getCertificateContents(String tagValue) throws CertificateException, IOException {

        tagValue = "-----BEGIN CERTIFICATE-----\n" + StringUtils.trim(tagValue) + "\n-----END CERTIFICATE-----";

        Certificate cert;
        try(InputStream inStream = new ByteArrayInputStream(tagValue.getBytes("UTF-8"))) {

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = cf.generateCertificate(inStream); // breaks here in V4
        }
        return cert.toString();
    }

    public static String getBase64Content(IContext context, IMendixObject certObj) throws IOException {
        String base64Content;
        try (InputStream inputStream = Core.getFileDocumentContent(context, certObj)) {
            base64Content = Base64.getEncoder().encodeToString(IOUtils.toByteArray(inputStream));
        }
        return base64Content;
    }
}
