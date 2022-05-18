package saml20.implementation.common;

public final class URLUtils {

    public static String ensureEndsWithSlash(String text) {
        return text.endsWith("/") ? text : text + "/";
    }
}