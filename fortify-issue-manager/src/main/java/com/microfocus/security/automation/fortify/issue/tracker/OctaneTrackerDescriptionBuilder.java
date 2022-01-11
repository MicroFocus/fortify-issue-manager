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

import com.microfocus.security.automation.fortify.issue.manager.BugTrackerDescriptionBuilder;
import com.microfocus.security.automation.fortify.issue.manager.models.Vulnerability;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class OctaneTrackerDescriptionBuilder implements BugTrackerDescriptionBuilder {

    @Override
    public String getIssueDescription(final String issueBaseUrl, final List<Vulnerability> vulnerabilities)
    {
        Collections.sort(vulnerabilities,
                Comparator.comparing(Vulnerability::getPrimaryLocation).thenComparing(Vulnerability::getId));
        final StringBuilder issues = new StringBuilder();
        issues.append("<table><body><tr><th>Issue Id</th><th>Description</th></tr>");
        for (final Vulnerability vulnerability : vulnerabilities) {
            issues.append("<tr>")
                    .append("<td><a href=\"" + issueBaseUrl + vulnerability.getId() + "\">" + vulnerability.getId() + "</a></td>")
                    .append("<td>" + vulnerability.getPrimaryLocation());
            if (vulnerability.getLineNumber() != null) {
                issues.append(" : ")
                        .append(vulnerability.getLineNumber());
            }
            issues.append("</td></tr>");
        }
        issues.append("</body></table>");
        return issues.toString();
    }

    @Override
    public String getOpenSourceIssueDescription(final String issueBaseUrl, final List<Vulnerability> vulnerabilities)
    {
        vulnerabilities.sort(Comparator.comparing(Vulnerability::getPrimaryLocation));
        final StringBuilder issues = new StringBuilder();
        issues.append("<table><body><tr><th>Issue Id</th><th>CVE ID</th><th>Component</th></tr>");
        for (final Vulnerability vulnerability : vulnerabilities) {
            issues.append("<tr>")
                    .append("<td><a href=\"" + issueBaseUrl + vulnerability.getId() + "\">" + vulnerability.getId() + "</a></td>")
                    .append("<td>" + vulnerability.getCheckId() + "</td>")
                    .append("<td>" + vulnerability.getPrimaryLocation());
            if (vulnerability.getLineNumber() != null) {
                issues.append(" : ")
                        .append(vulnerability.getLineNumber());
            }
            issues.append("</td></tr>");
        }
        issues.append("</body></table>");
        return issues.toString();
    }
}
