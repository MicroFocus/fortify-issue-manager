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
import com.microfocus.security.automation.fortify.issue.manager.BugTrackerDescriptionBuilder;
import com.microfocus.security.automation.fortify.issue.manager.ConfigurationException;

public class BugTrackerFactory {
    public static BugTracker getTracker(final String name) throws ConfigurationException {
        if (name.equalsIgnoreCase("JIRA")) {
            return new JiraTracker();
        } else if (name.equalsIgnoreCase("OCTANE")) {
            return new OctaneTracker();
        } else {
            throw new ConfigurationException("Tracker:" + name + "has not been configured");
        }
    }

    public static BugTrackerDescriptionBuilder getDescriptionBuilder(final String name) throws ConfigurationException {
        if (name.equalsIgnoreCase("JIRA")) {
            return new JiraTrackerDescriptionBuilder();
        } else if (name.equalsIgnoreCase("OCTANE")) {
            return new OctaneTrackerDescriptionBuilder();
        } else {
            throw new ConfigurationException("Tracker:" + name + "has not been configured");
        }
    }
}
