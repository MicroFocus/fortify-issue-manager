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

import com.google.common.net.UrlEscapers;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.microfocus.security.automation.fortify.issue.manager.BugTracker;
import com.microfocus.security.automation.fortify.issue.manager.BugTrackerException;
import com.microfocus.security.automation.fortify.issue.manager.BugTrackerSettings;
import com.microfocus.security.automation.fortify.issue.manager.ConfigurationException;

import java.io.IOException;

public final class OctaneRequestHandler extends BaseRequestHandler implements BugTracker
{
    private final TrackerClient client;
    final JsonParser parser;

    public OctaneRequestHandler() throws ConfigurationException
    {
        final BugTrackerSettings bugTrackerSettings = loadConfiguration();
        this.client = getClient(bugTrackerSettings);
        this.parser = new JsonParser();
    }

    @Override
    public String createBug(final String payload) throws BugTrackerException
    {
        try {
            // DDD replace this with correct api call
            final String issue = performPostRequest(client,"rest/api/2/issue", payload);

            // Parse the Response
            final JsonObject response = parser.parse(issue).getAsJsonObject();
            //  DDD what do we expect in the response from octane
            if (response.has("key")) {
                final String bugLink = response.get("key").getAsString();
                // DDD and this should be?
                return client.getApiUrl() + "/browse/" + UrlEscapers.urlPathSegmentEscaper().escape(bugLink);
            } else {
                // DDD how are errors communicated
                final String errors = response.get("errors").toString();
                throw new BugTrackerException(errors);
            }
        } catch (final IOException e) {
            throw new BugTrackerException(e);
        }
    }
}
