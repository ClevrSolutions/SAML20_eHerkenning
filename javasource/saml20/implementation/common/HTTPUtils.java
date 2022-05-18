package saml20.implementation.common;

import com.mendix.core.Core;
import com.mendix.logging.ILogNode;
import com.mendix.m2ee.api.IMxRuntimeRequest;
import com.mendix.m2ee.api.IMxRuntimeResponse;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.Response;
import saml20.implementation.wrapper.MxSAMLResponse;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Properties;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

public class HTTPUtils {

    protected static final ILogNode _logNode = Core.getLogger(Constants.LOGNODE);

    public static VelocityEngine getEngine() {
        VelocityEngine engine = new VelocityEngine();
        Properties p = new Properties();
        final String templateDir = Core.getConfiguration().getResourcesPath().getAbsolutePath() + File.separator + "SAML" + File.separator;
        p.setProperty("file.resource.loader.path", templateDir);
        p.setProperty("runtime.log", Core.getConfiguration().getTempPath().getAbsolutePath() + File.separator + "velocity.log");
        engine.init(p);

        return engine;
    }

    /**
     * Send a redirect using a meta tag.
     *
     * @param mxResponse Http response object.
     * @param url        URL to redirect to.
     * @throws IOException
     */
    public static void sendMetaRedirect(IMxRuntimeResponse mxResponse, String url, String query) throws IOException {
        mxResponse.setContentType("text/html");
        mxResponse.addHeader("Pragma", "no-cache");
        mxResponse.addHeader("Expires", "-1");
        mxResponse.addHeader("Cache-Control", "no-cache");
        mxResponse.addHeader("Cache-Control", "no-store");

        try (Writer writer = mxResponse.getWriter()) {
            writer.write("<html><head>");
            writer.write("<meta http-equiv=\"refresh\" content=\"0;url=");
            writer.write(url);
            if (query != null) {
                if (url.contains("?")) {
                    writer.write("&");
                } else {
                    writer.write("?");
                }
                writer.write(query);
            }
            writer.write("\">");
            writer.write("</head><body>");

            writer.write("</body></html>");
            writer.flush();
        }
    }

    public static boolean isSAMLResponse(HttpServletRequest request) {
        String responseParam = request.getParameter(Constants.SAML_SAMLRESPONSE);
        return responseParam != null && !responseParam.isEmpty();
    }

    public static boolean isSAMLRequest(HttpServletRequest request) {
        String responseParam = request.getParameter(Constants.SAML_SAMLREQUEST);
        return responseParam != null && !responseParam.isEmpty();
    }

    public static MxSAMLResponse extract(HttpServletRequest request) throws SAMLException {
        String samlResponse = request.getParameter(Constants.SAML_SAMLRESPONSE);
        if (samlResponse == null || samlResponse.trim().isEmpty()) {
            // 2015-05-07: Removed "temp hack" that was present here
            throw new IllegalStateException("SAMLResponse parameter cannot be null");
        }

        String xml = new String(Base64.getMimeDecoder().decode(samlResponse), StandardCharsets.UTF_8);
        XMLObject obj = SAMLUtil.unmarshallElementFromString(xml);
        if (!(obj instanceof Response)) {
            throw new IllegalArgumentException("SAMLResponse must be of type Response. Was " + obj);
        }
        return new MxSAMLResponse((Response) obj);
    }

    public static <T extends SignableSAMLObject> T extractSAMLRequest(HttpServletRequest request) throws SAMLException {
        return extractSAMLObject(request, Constants.SAML_SAMLREQUEST);
    }

    public static <T extends SignableSAMLObject> T extractSAMLResponse(HttpServletRequest request) throws SAMLException {
        return extractSAMLObject(request, Constants.SAML_SAMLRESPONSE);
    }

    @SuppressWarnings("unchecked")
    private static <T extends SignableSAMLObject> T extractSAMLObject(HttpServletRequest request, String httpParameter) throws SAMLException {
        String samlResponseBase64 = request.getParameter(httpParameter);
        byte[] samlResponseBytes = Base64.getMimeDecoder().decode(samlResponseBase64);

        if (samlResponseBase64 == null || samlResponseBase64.trim().isEmpty()) {
            // 2015-05-07: Removed "temp hack" that was present here
            throw new IllegalStateException("SAMLResponse parameter cannot be null");
        }

        try {
            // BJHL 2015-10-23 For a redirect binding, the message is usually deflate compressed.
            String samlResponseXML = attemptInflate(samlResponseBytes);

            XMLObject obj = SAMLUtil.unmarshallElementFromString(samlResponseXML);
            if (obj instanceof SignableSAMLObject) {
                return (T) obj;
            } else {
                throw new IllegalArgumentException("SAMLResponse must be a SignableSAMLObject. Was " + obj);
            }
        } catch (UnsupportedEncodingException e) {
            throw new SAMLException(e);
        }
    }

    private static String attemptInflate(byte[] samlBytes) throws UnsupportedEncodingException {
        final String encoding = "UTF-8";
        try (ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
             InflaterOutputStream inflaterStream = new InflaterOutputStream(bytesOut, new Inflater(true))) {
            inflaterStream.write(samlBytes);
            // return the uncompressed version
            return bytesOut.toString(encoding);
        } catch (IOException e) {
            // it was not compressed, return original. If it is not UTF-8, this will throw UnsupportedEncodingException
            return new String(samlBytes, encoding);
        }// some other exception occurred during decompression, assume it's not compressed and return original

    }

    public static void redirect(IMxRuntimeResponse response, String path) {
        response.setStatus(HttpServletResponse.SC_SEE_OTHER);
        response.addHeader("location", path);
    }

    public static String[] decodeDiscoveryValue(String value) {
        if (value == null) {
            return new String[0];
        }
        String[] ids = value.split(" ");
        for (int i = 0; i < ids.length; i++) {
            ids[i] = new String(Base64.getMimeDecoder().decode(ids[i]));
        }
        return ids;
    }

    public static String[] extractResourceArguments(IMxRuntimeRequest request) {
        String requestResourcePath = request.getResourcePath();
        String[] resourceArgs = requestResourcePath.substring(1).split("/");
        switch (resourceArgs.length) {
            // When there are no arguments or just one we only have the /SSO/ in the url, so do nothing.
            case 0:
            case 1:
                resourceArgs = new String[]{"", ""};
                break;
            case 2:
                resourceArgs = new String[]{resourceArgs[1], ""};
                break;
            default:
                resourceArgs = new String[]{resourceArgs[1], resourceArgs[2]};
                break;
        }

        return resourceArgs;
    }

    public static String appendParamToUrl(String url, String paramName,
                                          String paramValue) {
        return url + (url.contains("?") ? "&" : "?") + urlEncode(paramName) + "=" + urlEncode(paramValue);
    }

    public static String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

}
