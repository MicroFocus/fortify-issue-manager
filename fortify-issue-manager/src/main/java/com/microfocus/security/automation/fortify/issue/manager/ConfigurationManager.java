/*
 * Copyright 2020 Micro Focus or one of its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.microfocus.security.automation.fortify.issue.manager;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class ConfigurationManager {
    private static final Logger LOGGER = LoggerFactory.getLogger(ConfigurationManager.class);

    public static Map<String, String> getProxySetting(final String proxyEnvVariable)
    {
        final Map<String, String> proxySettings = new HashMap<>();

        final String proxy = System.getenv(proxyEnvVariable);
        if (proxy != null) {
            try {
                final URI uri = new URI(proxy);
                final String host = uri.getHost();
                if (host != null) {
                    proxySettings.put("host", host);
                    final int port = uri.getPort();
                    proxySettings.put("port", port != -1 ? port + "" : "80");
                } else {
                    LOGGER.error("Misconfigured {}, host name can't be null.", proxyEnvVariable);
                }
            } catch (final URISyntaxException ex) {
                LOGGER.error(ex.getMessage(), ex);
            }
        }
        return proxySettings;
    }

    public static String getConfig(final String configName, final List<String> errorConfigs)
    {
        final String configValue = System.getenv(configName);
        if (StringUtils.isEmpty(configValue)) {
            errorConfigs.add(configName);
        }
        return configValue;
    }
}
