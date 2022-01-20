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

import com.microfocus.security.automation.fortify.issue.manager.BugTracker;
import com.microfocus.security.automation.fortify.issue.manager.ConfigurationException;
import com.microfocus.security.automation.fortify.issue.manager.ConfigurationManager;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class BugTrackerFactory {

    private final static Map<String, String> proxySettings = ConfigurationManager.getProxySetting("HTTP_PROXY");;
    private final static List<String> configErrors = new ArrayList<>();;
    private final static String bugTrackerUsername = ConfigurationManager.getConfig("TRACKER_USERNAME", configErrors);;
    private final static String bugTrackerPassword = ConfigurationManager.getConfig("TRACKER_PASSWORD", configErrors);;
    private final static String bugTrackerApiUrl = ConfigurationManager.getConfig("TRACKER_API_URL", configErrors);;

    public static BugTracker getTracker(
            final String name) throws ConfigurationException {
        if (name.equalsIgnoreCase("JIRA")) {
            if (!configErrors.isEmpty()) {
                throw new ConfigurationException("Invalid Jira configuration " + configErrors);
            }
            final BugTrackerSettings jiraSettings = new BugTrackerSettings(
                bugTrackerUsername,
                bugTrackerPassword,
                bugTrackerApiUrl,
                proxySettings
            );
            return new JiraTracker(jiraSettings);
        } else if (name.equalsIgnoreCase("OCTANE")) {
            final String workspaceId = ConfigurationManager.getConfig("TRACKER_WORKSPACE_ID", configErrors);
            final String sharedSpaceId = ConfigurationManager.getConfig("TRACKER_SHARED_SPACE_ID", configErrors);

            if (!configErrors.isEmpty()) {
                throw new ConfigurationException("Invalid Octane configuration " + configErrors);
            }

            final OctaneBugTrackerSettings octaneSettings =  new OctaneBugTrackerSettings(
                bugTrackerUsername,
                bugTrackerPassword,
                bugTrackerApiUrl,
                sharedSpaceId,
                workspaceId,
                proxySettings
            );
            return new OctaneTracker(octaneSettings);
        } else {
            throw new ConfigurationException("Tracker:" + name + "has not been configured");
        }
    }
}
