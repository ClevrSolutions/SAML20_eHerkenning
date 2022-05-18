package saml20.implementation;

import com.mendix.core.Core;
import com.mendix.logging.ILogNode;
import org.opensaml.saml.common.SAMLException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import saml20.implementation.common.Constants;
import saml20.implementation.metadata.SPMetadataGenerator;
import saml20.implementation.security.CredentialRepository;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class MetadataHandler extends SAMLHandler {
    private static final ILogNode _logNode = Core.getLogger(Constants.LOGNODE);

    @Override
    public void handleRequest(SAMLRequestContext context) throws SAMLException {
        printTraceInfo(context);
        printMetadata(context);
    }

    private static void printMetadata(SAMLRequestContext context) throws SAMLException {
        try (OutputStream out = context.getResponse().getOutputStream();
             ByteArrayOutputStream stream = SPMetadataGenerator.generate(context.getIContext(),
                     context.getSpMetadata().getSpMetadataObject(), CredentialRepository.getInstance())
        ) {
            out.write(stream.toByteArray());

        } catch (IOException e) {
            throw new SAMLException("Unable to write metadata back in the response", e);
        }
    }

}
