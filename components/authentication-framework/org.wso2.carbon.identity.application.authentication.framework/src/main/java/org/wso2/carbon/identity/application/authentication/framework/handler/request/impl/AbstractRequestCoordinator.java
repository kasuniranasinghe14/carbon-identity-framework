/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authentication.framework.handler.request.impl;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.loader.SequenceLoader;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.RequestCoordinator;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

/**
 * Abstract implementation for the request coordinator.
 *
 */
public abstract class AbstractRequestCoordinator implements RequestCoordinator {

    private static Log log = LogFactory.getLog(AbstractRequestCoordinator.class);

    /**
     * Returns the sequence config related to current Authentication Context.
     * @param context  Authentication Context
     * @param parameterMap Parameter Map, retrieved from (Http/etc) Request.
     * @return Generated Sequence Config.
     * @throws FrameworkException when there is an error in loading the Sequence Config, most probably error
     * in underlying data persistence layer.
     */
    public SequenceConfig getSequenceConfig(AuthenticationContext context, Map<String, String[]> parameterMap)
            throws FrameworkException {
        String requestType = context.getRequestType();
        String[] issuers = parameterMap.get(FrameworkConstants.RequestParams.ISSUER);
        String issuer = null;
        if (!ArrayUtils.isEmpty(issuers)) {
            issuer = issuers[0];
        }
        String tenantDomain = context.getTenantDomain();

        SequenceLoader sequenceBuilder = FrameworkServiceDataHolder.getInstance().getSequenceLoader();
        if (sequenceBuilder != null) {
            ServiceProvider serviceProvider = getServiceProvider(requestType, issuer, tenantDomain);
            return sequenceBuilder.getSequenceConfig(context, parameterMap, serviceProvider);
        } else {
            //Backward compatibility, Using the deprecated method.
            //TODO: Need to remove the dependency to this.
            return ConfigurationFacade.getInstance().getSequenceConfig(issuer, requestType, tenantDomain);
        }

    }

    /**
     * Returns the service provider form persistence layer.
     */
    protected ServiceProvider getServiceProvider(String reqType, String clientId, String tenantDomain)
            throws FrameworkException {

        ApplicationManagementService appInfo = ApplicationManagementService.getInstance();

        // special case for OpenID Connect, these clients are stored as OAuth2 clients
        if ("oidc".equals(reqType)) {
            reqType = "oauth2";
        }

        ServiceProvider serviceProvider;

        if (StringUtils.equals(reqType, "cas")) {
            URL url = null;
            try {
                url = new URL(clientId);
            } catch (MalformedURLException e) {
                throw new FrameworkException("Error occurred while retrieving service provider for client ID: " +
                        clientId + " and tenant: " + tenantDomain, e);
            }

            // baseUrl MUST match the CAS Configuration Service Url.
            clientId = url.getProtocol() + "://" + url.getHost();
            if (url.getPort() != -1) {
                clientId = clientId + ":" + url.getPort();
            }

            // Remove info log and uncomment debug log after testing the fix.
            log.info("Resolved url as clientId for cas request: " + clientId);
            //        if (log.isDebugEnabled()) {
            //            log.debug("Resolved url as clientId for cas request: " + clientId);
            //        }
        }

        try {
            serviceProvider = appInfo.getServiceProviderByClientId(clientId, reqType, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new FrameworkException("Error occurred while retrieving service provider for client ID: " + clientId
                    + " and tenant: " + tenantDomain, e);
        }
        return serviceProvider;
    }
}
