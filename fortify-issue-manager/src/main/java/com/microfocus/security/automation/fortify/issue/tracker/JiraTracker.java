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

import java.io.IOException;

import com.microfocus.security.automation.fortify.issue.manager.BugTracker;
import com.microfocus.security.automation.fortify.issue.manager.ConfigurationException;
import com.microfocus.security.automation.fortify.issue.manager.BugTrackerException;

import com.google.common.net.UrlEscapers;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public final class JiraTracker extends BaseTracker implements BugTracker
{
    private final TrackerClient client;
    private final JsonParser parser;

    public JiraTracker() throws ConfigurationException
    {
        super();
        this.client = getClient();
        this.parser = new JsonParser();
    }

    @Override
    public String createBug(final String payload) throws BugTrackerException
    {
        try {
            final String issue = performPostRequest(client,"rest/api/2/issue", payload);

            // Parse the Response
            final JsonObject response = parser.parse(issue).getAsJsonObject();
            if (response.has("key")) {
                final String bugLink = response.get("key").getAsString();
                return client.getApiUrl() + "/browse/" + UrlEscapers.urlPathSegmentEscaper().escape(bugLink);
            } else {
                final String errors = response.get("errors").toString();
                throw new BugTrackerException(errors);
            }
        } catch (final IOException e) {
            throw new BugTrackerException(e);
        }
    }
}
