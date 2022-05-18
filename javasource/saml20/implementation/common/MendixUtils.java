package saml20.implementation.common;

import com.mendix.core.Core;
import com.mendix.datastorage.XPathBasicQuery;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IMendixIdentifier;
import com.mendix.systemwideinterfaces.core.IMendixObject;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigDecimal;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public final class MendixUtils {

    public static <T> List<T> mendixObjectListToProxyObjectList(final IContext context, final List<IMendixObject> list, final Class<T> cls) {
        return list
                .stream()
                .map(mendixObject -> mendixObjectToProxyObject(context, mendixObject, cls))
                .collect(Collectors.toList());
    }

    @SuppressWarnings("unchecked")
    private static <T> T mendixObjectToProxyObject(final IContext context, final IMendixObject mendixObject, final Class<T> cls) {
        if (mendixObject != null) {
            try {
                final Method initialize = cls.getMethod("initialize", IContext.class, IMendixObject.class);
                //noinspection unchecked
                return (T) initialize.invoke(null, context, mendixObject);
            } catch (InvocationTargetException | IllegalAccessException | NoSuchMethodException e) {
                return null;
            }
        } else {
            return null;
        }
    }

    public static List<IMendixObject> retrieveFromDatabase(final IContext context, final String xPathExpr,
                                                           final Map<String, Object> xPathVariables, final Object... xPathArgs) {

        return retrieveFromDatabase(context, -1, 0, null, 0, xPathExpr, xPathVariables, xPathArgs);
    }

    public static List<IMendixObject> retrieveFromDatabase(final IContext context,
                                                           final int amount, final int offset, final LinkedHashMap<String, Boolean> sorting,
                                                           final int depth,
                                                           final String xPathExpr,
                                                           final Map<String, Object> xPathVariables,
                                                           final Object... xPathArgs) {

        final XPathBasicQuery query = Core.createXPathQuery(String.format(xPathExpr, xPathArgs));
        query.setAmount(amount);
        query.setOffset(offset);
        query.setDepth(depth);

        if (xPathVariables != null && !xPathVariables.isEmpty()) {
            for (Map.Entry<String, Object> variable : xPathVariables.entrySet()) {
                setXPathQueryVariable(query, variable.getKey(), variable.getValue());
            }
        }

        if (sorting != null && !sorting.isEmpty()) {
            for (Map.Entry<String, Boolean> sortingEntry : sorting.entrySet()) {
                query.addSort(sortingEntry.getKey(), sortingEntry.getValue());
            }
        }

        return query.execute(context);
    }

    private static void setXPathQueryVariable(final XPathBasicQuery query, final String key, final Object val) {

        if (val instanceof BigDecimal) {
            query.setVariable(key, (BigDecimal) val);
        } else if (val instanceof Boolean) {
            query.setVariable(key, (boolean) val);
        } else if (val instanceof Double) {
            query.setVariable(key, (double) val);
        } else if (val instanceof Integer) {
            query.setVariable(key, (int) val);
        } else if (val instanceof Long) {
            query.setVariable(key, (long) val);
        } else if (val instanceof IMendixObject) {
            query.setVariable(key, (IMendixObject) val);
        } else if (val instanceof IMendixIdentifier) {
            query.setVariable(key, (IMendixIdentifier) val);
        } else if (val instanceof String) {
            query.setVariable(key, val.toString());
        } else {
            throw new RuntimeException("Unsupported variable type: " + val.getClass().getCanonicalName() + " provided for key: " + key);
        }
    }

}
