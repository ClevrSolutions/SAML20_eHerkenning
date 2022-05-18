package saml20.implementation.metadata;

import com.mendix.core.Core;
import com.mendix.logging.ILogNode;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import saml20.implementation.common.Constants;
import saml20.implementation.common.SAMLUtil;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public abstract class IMetadata {

    protected static final ILogNode _logNode = Core.getLogger(Constants.LOGNODE);

    public static List<EntityDescriptor> getListOfIdpMetadata(InputStream inputStream) throws SAMLException {
        List<EntityDescriptor> descriptors = new ArrayList<EntityDescriptor>();
        String protocol = Constants.PROTOCOL;

        File idpFile = new File(Core.getConfiguration().getTempPath().getAbsolutePath() + "/saml_IdPFile" + System.currentTimeMillis() + ".xml");

        try (FileOutputStream outputStream = new FileOutputStream(idpFile)) {
            int read = 0;
            byte[] bytes = new byte[1024];

            while ((read = inputStream.read(bytes)) != -1) {
                outputStream.write(bytes, 0, read);
            }
        } catch (IOException e) {
            throw new SAMLException("Unable to create a local copy of the IdP file for pre-processing", e);
        }

        _logNode.info("Loading " + protocol + " metadata from " + idpFile);
        try {
            XMLObject descriptor = SAMLUtil.unmarshallElementFromFile(idpFile.getAbsolutePath());
            if (descriptor instanceof EntityDescriptor) {
                descriptors.add((EntityDescriptor) descriptor);
            } else if (descriptor instanceof EntitiesDescriptor) {
                EntitiesDescriptor desc = (EntitiesDescriptor) descriptor;
                descriptors.addAll(desc.getEntityDescriptors());
            } else {
                throw new RuntimeException("Metadata file " + idpFile + " does not contain an EntityDescriptor. Found " + descriptor.getElementQName() + ", expected " + EntityDescriptor.ELEMENT_QNAME);
            }
        } catch (RuntimeException e) {
            _logNode.error("Unable to load metadata from " + idpFile + ". File must contain valid XML and have EntityDescriptor as top tag", e);
            throw e;
        }

        idpFile.deleteOnExit();

        if (descriptors.isEmpty()) {
            throw new SAMLException("No IdP descriptors found in ! At least one file is required.");
        }

        return descriptors;
    }
}
