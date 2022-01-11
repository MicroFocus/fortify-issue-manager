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
import com.microfocus.security.automation.fortify.issue.manager.ConfigurationException;
import com.microfocus.security.automation.fortify.issue.manager.models.Vulnerability;
import org.hamcrest.CoreMatchers;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.Assert;
import org.junit.rules.ErrorCollector;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class OctaneTrackerDescriptionBuilderTest {

    private static List<Vulnerability> vulnerabilities;
    private static Map<String, String> tables;

    public static BugTrackerDescriptionBuilder descriptionBuilder(final String trackerName)
            throws ConfigurationException {
        return BugTrackerFactory.getDescriptionBuilder(trackerName);
    }

    @BeforeClass
    public static void setup() {
        vulnerabilities = new ArrayList<>();
        tables = new HashMap<>();
        tables.put("OSJ", "||Issue Id||CVE ID||Component||");
        tables.put("OSO", "<table><body><tr><th>Issue Id</th><th>CVE ID</th><th>Component</th></tr></body></table>");
        tables.put("NOSJ", "||Issue Id||Description||");
        tables.put("NOSO", "<table><body><tr><th>Issue Id</th><th>Description</th></tr></body></table>");
    }

    @Rule
    public ErrorCollector errorCollector = new ErrorCollector();

    @Test
    public void testGetIssueDescriptionForJira() {
        testGetIssueDescription("jira", "NOSJ");
        testGetOpenSourceIssueDescription("jira", "OSJ");
        testGetIssueDescription("JIRA", "NOSJ");
        testGetOpenSourceIssueDescription("JIRA", "OSJ");
    }

    @Test
    public void testGetIssueDescriptionForOctane() {
        testGetIssueDescription("octane", "NOSO");
        testGetOpenSourceIssueDescription("octane", "OSO");
        testGetIssueDescription("OCTANE", "NOSO");
        testGetOpenSourceIssueDescription("OCTANE", "OSO");
    }

    public void testGetIssueDescription(final String tracker, final String src) {
        final BugTrackerDescriptionBuilder builder;
        try {
            builder = descriptionBuilder(tracker);
            Assert.assertNotNull("Description build should not be null", builder);
            final String description = builder.getIssueDescription("baseUrl/for/test", vulnerabilities);
            errorCollector.checkThat("Failed to build description", description, CoreMatchers.notNullValue());
            errorCollector.checkThat("Failed to build description", description, CoreMatchers.is(tables.get(src)));
        } catch (final ConfigurationException e) {
            errorCollector.addError(new AssertionError("Failed to load description builder"));
        }
    }

    public void testGetOpenSourceIssueDescription(final String tracker, final String src) {
        final BugTrackerDescriptionBuilder builder;
        try {
            builder = descriptionBuilder(tracker);
            Assert.assertNotNull("Description build should not be null", builder);
            final String description = builder.getOpenSourceIssueDescription("baseUrl/for/test", vulnerabilities);
            errorCollector.checkThat("Failed to build description", description, CoreMatchers.notNullValue());
            errorCollector.checkThat("Failed to build description", description, CoreMatchers.is(tables.get(src)));
        } catch (final ConfigurationException e) {
            errorCollector.addError(new AssertionError("Failed to load description builder"));
        }
    }
}