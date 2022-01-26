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
import com.microfocus.security.automation.fortify.issue.manager.ConfigurationException;
import com.microfocus.security.automation.fortify.issue.manager.models.Vulnerability;

import java.io.IOException;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public final class JiraTracker implements BugTracker {

    private final JiraTrackerClient client;
    private final static JsonParser parser = new JsonParser();
    private final String apiUrl;

    JiraTracker(final BugTrackerSettings bugTrackerSettings) {
        super();
        this.apiUrl = bugTrackerSettings.getApiUrl();
        this.client = new JiraTrackerClient(bugTrackerSettings);
    }

    @Override
    public String createBug(final String payload) throws BugTrackerException {
        try {
            final String issue = client.performPostRequest(payload);

            // Parse the Response
            final JsonObject response = parser.parse(issue).getAsJsonObject();
            if (response.has("key")) {
                final String bugLink = response.get("key").getAsString();
                return apiUrl + "/browse/" + UrlEscapers.urlPathSegmentEscaper().escape(bugLink);
            } else {
                final String errors = response.get("errors").toString();
                throw new BugTrackerException(errors);
            }
        } catch (final IOException | ConfigurationException e) {
            throw new BugTrackerException(e);
        }
    }

    @Override
    public String getIssueDescription(final String issueBaseUrl, final List<Vulnerability> vulnerabilities) {
        Collections.sort(vulnerabilities,
            Comparator.comparing(Vulnerability::getPrimaryLocation).thenComparing(Vulnerability::getId));

        final StringBuilder issues = new StringBuilder();
        issues.append("||Issue Id||Description||");
        for (final Vulnerability vulnerability : vulnerabilities) {
            issues.append("\n|[")
                .append(vulnerability.getId())
                .append("|")
                .append(issueBaseUrl)
                .append(vulnerability.getId())
                .append("]|")
                .append(vulnerability.getPrimaryLocation());
            if (vulnerability.getLineNumber() != null) {
                issues.append(" : ")
                    .append(vulnerability.getLineNumber());
            }
            issues.append("|");
        }
        return issues.toString();
    }

    @Override
    public String getOpenSourceIssueDescription(final String issueBaseUrl, final List<Vulnerability> vulnerabilities) {
        vulnerabilities.sort(Comparator.comparing(Vulnerability::getPrimaryLocation));

        final StringBuilder issues = new StringBuilder();
        issues.append("||Issue Id||CVE ID||Component||");
        for (final Vulnerability vulnerability : vulnerabilities) {
            issues.append("\n|[")
                .append(vulnerability.getId())
                .append("|")
                .append(issueBaseUrl)
                .append(vulnerability.getId())
                .append("]|")
                .append(vulnerability.getCheckId())
                .append("|")
                .append(vulnerability.getPrimaryLocation());
            if (vulnerability.getLineNumber() != null) {
                issues.append(" : ")
                    .append(vulnerability.getLineNumber());
            }
            issues.append("|");
        }
        return issues.toString();
    }
}
