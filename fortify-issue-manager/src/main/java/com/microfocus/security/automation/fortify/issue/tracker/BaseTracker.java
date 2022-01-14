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
package com.microfocus.security.automation.fortify.issue.tracker;

import com.microfocus.security.automation.fortify.issue.manager.BugTrackerException;
import com.microfocus.security.automation.fortify.issue.manager.ConfigurationException;
import com.microfocus.security.automation.fortify.issue.manager.ConfigurationManager;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class BaseTracker {
    protected Map<String, String> proxySettings;
    protected List<String> configErrors;
    protected String bugTrackerUsername;
    protected String bugTrackerPassword;
    protected String bugTrackerApiUrl;
    protected final ConfigurationManager configurationManager;

    BaseTracker(final ConfigurationManager cfg) throws ConfigurationException {
        configurationManager = cfg;
        loadConfiguration();
    }

    /**
     * Load common cfg.
     *
     * @throws ConfigurationException
     */
    private void loadConfiguration() throws ConfigurationException {
        proxySettings = configurationManager.getProxySetting("HTTP_PROXY");
        configErrors = new ArrayList<>();

        // Get bug tracker settings
        bugTrackerUsername = configurationManager.getConfig("TRACKER_USERNAME", configErrors);
        bugTrackerPassword = configurationManager.getConfig("TRACKER_PASSWORD", configErrors);
        bugTrackerApiUrl = configurationManager.getConfig("TRACKER_API_URL", configErrors);

        if (!configErrors.isEmpty()) {
            throw new ConfigurationException("Invalid configuration " + configErrors);
        }
    }
}
