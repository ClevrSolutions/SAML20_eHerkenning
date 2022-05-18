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

import com.mendix.core.Core;
import com.mendix.logging.ILogNode;
import org.apache.commons.pool2.BaseKeyedPooledObjectFactory;
import org.apache.commons.pool2.PooledObject;
import org.apache.commons.pool2.impl.DefaultPooledObject;
import org.apache.commons.pool2.impl.GenericKeyedObjectPool;
import saml20.implementation.common.Constants;

import javax.xml.namespace.NamespaceContext;
import javax.xml.namespace.QName;
import javax.xml.xpath.*;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * @source https://github.com/Jasig/uPortal/tree/fb42cf9525325f6fea234bf9593910e0ef45d51f
 */


@SuppressWarnings("rawtypes")
public class XPathExpressionPool implements XPathExpressionExecutor {
    protected final ILogNode logger = Core.getLogger(Constants.LOGNODE);
    
    private final GenericKeyedObjectPool pool;
    private final NamespaceContext namespaceContext;
	private final ThreadLocalXPathVariableResolver variableResolver = new ThreadLocalXPathVariableResolver();
	
    public XPathExpressionPool() {
        this(null);
    }
    
//    @SuppressWarnings("unchecked")
//	public XPathExpressionPool(NamespaceContext namespaceContext) {
//        this.namespaceContext = namespaceContext;
//        
//        final XPathExpressionFactory xpathExpressionfactory = new XPathExpressionFactory();
//        this.pool = new GenericKeyedObjectPool(xpathExpressionfactory);
//        this.pool.setMaxActive(100);
//        this.pool.setMaxIdle(100);
//        this.pool.setTimeBetweenEvictionRunsMillis(TimeUnit.SECONDS.toMillis(60));
//        this.pool.setMinEvictableIdleTimeMillis(TimeUnit.MINUTES.toMillis(5));
//        this.pool.setNumTestsPerEvictionRun(this.pool.getMaxIdle() / 6);
//    }
    
	@SuppressWarnings("unchecked")
	public XPathExpressionPool(NamespaceContext namespaceContext) {
		this.namespaceContext = namespaceContext;

		final XPathExpressionFactory xpathExpressionfactory = new XPathExpressionFactory(this.namespaceContext,
				variableResolver);
		this.pool = new GenericKeyedObjectPool(xpathExpressionfactory);
		this.pool.setMaxTotalPerKey(100);
		this.pool.setMaxIdlePerKey(100);
		this.pool.setTimeBetweenEvictionRunsMillis(TimeUnit.SECONDS.toMillis(60));
		this.pool.setMinEvictableIdleTimeMillis(TimeUnit.MINUTES.toMillis(5));
		this.pool.setNumTestsPerEvictionRun(this.pool.getMaxIdlePerKey() / 9);
	}   
    
    @Override
    protected void finalize() throws Throwable {
        this.pool.close();
    }

    @SuppressWarnings("unchecked")
	public <T> T doWithExpression(String expression, XPathExpressionCallback<T> callback) throws XPathExpressionException {
        if (this.logger.isDebugEnabled()) {
            this.logger.debug("Pooled expression " + expression + ": active=" + this.pool.getNumActive(expression) + ", idle=" +  this.pool.getNumIdle(expression));
        }
        
        try {
            final XPathExpression xPathExpression = (XPathExpression)this.pool.borrowObject(expression);
            try {
                return callback.doWithExpression(xPathExpression);
            }
            finally {
                this.pool.returnObject(expression, xPathExpression);
            }
        }
        catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException)e;
            }
            if (e instanceof XPathExpressionException) {
                throw (XPathExpressionException)e;
            }
            throw new IllegalStateException("Exception of type " + e.getClass().getName() + " is not expected", e);
        }
    }
    
    /* (non-Javadoc)
     * @see org.jasig.portal.security.provider.saml.XPathExpressionExecutor#evaluate(java.lang.String, java.lang.Object, javax.xml.namespace.QName)
     */
    @Override
	public <T> T evaluate(String expression, final Object item, final QName returnType) throws XPathExpressionException {
        return this.doWithExpression(expression, new XPathExpressionCallback<T>() {
            @Override
			@SuppressWarnings("unchecked")
            public T doWithExpression(XPathExpression xPathExpression) throws XPathExpressionException {
                return (T)xPathExpression.evaluate(item, returnType);
            }
        });
    }
    
    public interface XPathExpressionCallback<T> {
        T doWithExpression(XPathExpression xPathExpression) throws XPathExpressionException;
    }
    
	private class ThreadLocalXPathVariableResolver implements XPathVariableResolver {
		private final ThreadLocal<Map<String, ?>> localVariables = new ThreadLocal<Map<String, ?>>();

		@SuppressWarnings("unused")
		public void setVariables(Map<String, ?> variables) {
			this.localVariables.set(variables);
		}

		@SuppressWarnings("unused")
		public void clearVariables() {
			this.localVariables.set(null);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * javax.xml.xpath.XPathVariableResolver#resolveVariable(javax.xml.namespace.
		 * String)
		 */
		@Override
		public Object resolveVariable(QName variableName) {
			final Map<String, ?> variables = this.localVariables.get();
			if (variables == null) {
				return null;
			}

			final String localPart = variableName.getLocalPart();
			return variables.get(localPart);
		}
	}
    
	private class XPathExpressionFactory extends BaseKeyedPooledObjectFactory<String, XPathExpression> {
		private final XPathFactory xPathFactory = XPathFactory.newInstance();
		private final NamespaceContext namespaceContext;
		private final XPathVariableResolver variableResolver;

		public XPathExpressionFactory(NamespaceContext namespaceContext, XPathVariableResolver variableResolver) {
			this.namespaceContext = namespaceContext;
			this.variableResolver = variableResolver;
		}

		@Override
		public PooledObject<XPathExpression> wrap(XPathExpression obj) {
			return new DefaultPooledObject<>(obj);
		}

		@Override
		public synchronized PooledObject<XPathExpression> makeObject(String key)
				throws RuntimeException, XPathExpressionException {
			final String expression = (String) key;

			final XPath xPath = this.xPathFactory.newXPath();
			if (XPathExpressionPool.this.namespaceContext != null) {
				xPath.setNamespaceContext(XPathExpressionPool.this.namespaceContext);
			}

			XPathExpressionPool.this.logger.debug("Creating XPathExpression from: " + expression);

			return wrap(xPath.compile(expression));
		}

		@Override
		public synchronized XPathExpression create(String key) throws RuntimeException {
			final String expression = key;

			final XPath xPath = xPathFactory.newXPath();
			if (this.namespaceContext != null) {
				xPath.setNamespaceContext(this.namespaceContext);
			}
			if (this.variableResolver != null) {
				xPath.setXPathVariableResolver(this.variableResolver);
			}

			XPathExpressionPool.this.logger.debug("Compiling XPathExpression from: " + expression);

			try {
				return xPath.compile(expression);
			} catch (XPathExpressionException e) {
				throw new RuntimeException("Failed to compile XPath expression '" + expression + "'", e);
			}
		}

		@Override
		public void destroyObject(String key, PooledObject<XPathExpression> obj) throws RuntimeException {
			final String expression = (String) key;
			XPathExpressionPool.this.logger.debug("Destroying XPathExpression: " + expression);
		}
	}
    
	public void clear() {
		pool.clear();
	}

	public void clearOldest() {
		pool.clearOldest();
	}

	public void close() throws Exception {
		pool.close();
	}

	public void evict() throws Exception {
		pool.evict();
	}

	public boolean getLifo() {
		return pool.getLifo();
	}

	public int getMaxTotalPerKey() {
		return pool.getMaxTotalPerKey();
	}

	public int getMaxIdlePerKey() {
		return pool.getMaxIdlePerKey();
	}

	public int getMaxTotal() {
		return pool.getMaxTotal();
	}

	public long getMaxWaitMillis() {
		return pool.getMaxWaitMillis();
	}

	public long getMinEvictableIdleTimeMillis() {
		return pool.getMinEvictableIdleTimeMillis();
	}

	public int getMinIdlePerKey() {
		return pool.getMinIdlePerKey();
	}

	public int getNumActive() {
		return pool.getNumActive();
	}

	public int getNumIdle() {
		return pool.getNumIdle();
	}

	public int getNumTestsPerEvictionRun() {
		return pool.getNumTestsPerEvictionRun();
	}

	public boolean getTestOnBorrow() {
		return pool.getTestOnBorrow();
	}

	public boolean getTestOnReturn() {
		return pool.getTestOnReturn();
	}

	public boolean getTestWhileIdle() {
		return pool.getTestWhileIdle();
	}

	public long getTimeBetweenEvictionRunsMillis() {
		return pool.getTimeBetweenEvictionRunsMillis();
	}

	public void setLifo(boolean lifo) {
		pool.setLifo(lifo);
	}

	public void setMaxTotalPerKey(int maxActive) {
		pool.setMaxTotalPerKey(maxActive);
	}

	public void setMaxIdlePerKey(int maxIdle) {
		pool.setMaxIdlePerKey(maxIdle);
	}

	public void setMaxTotal(int maxTotal) {
		pool.setMaxTotal(maxTotal);
	}

	public void setMaxWaitMillis(long maxWait) {
		pool.setMaxWaitMillis(maxWait);
	}

	public void setMinEvictableIdleTimeMillis(long minEvictableIdleTimeMillis) {
		pool.setMinEvictableIdleTimeMillis(minEvictableIdleTimeMillis);
	}

	public void setMinIdlePerKey(int poolSize) {
		pool.setMinIdlePerKey(poolSize);
	}

	public void setNumTestsPerEvictionRun(int numTestsPerEvictionRun) {
		pool.setNumTestsPerEvictionRun(numTestsPerEvictionRun);
	}

	public void setTestOnBorrow(boolean testOnBorrow) {
		pool.setTestOnBorrow(testOnBorrow);
	}

	public void setTestOnReturn(boolean testOnReturn) {
		pool.setTestOnReturn(testOnReturn);
	}

	public void setTestWhileIdle(boolean testWhileIdle) {
		pool.setTestWhileIdle(testWhileIdle);
	}

	public void setTimeBetweenEvictionRunsMillis(long timeBetweenEvictionRunsMillis) {
		pool.setTimeBetweenEvictionRunsMillis(timeBetweenEvictionRunsMillis);
	}
}
