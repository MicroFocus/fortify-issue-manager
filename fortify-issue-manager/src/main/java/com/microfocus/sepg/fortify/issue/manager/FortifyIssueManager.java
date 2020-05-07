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
package com.microfocus.sepg.fortify.issue.manager;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import com.google.common.base.Joiner;
import com.microfocus.sepg.fortify.issue.manager.models.Application;
import com.microfocus.sepg.fortify.issue.manager.models.Category;
import com.microfocus.sepg.fortify.issue.manager.models.Release;
import com.microfocus.sepg.fortify.issue.manager.models.Vulnerability;
import com.microfocus.sepg.fortify.issue.tracker.BugTrackerException;
import com.microfocus.sepg.fortify.issue.tracker.JiraRequestHandler;

public final class FortifyIssueManager
{
    private static final Logger LOGGER = LoggerFactory.getLogger(FortifyIssueManager.class);
    private final String FORTIFY_ISSUE_LINK_FORMAT = "%s/Releases/%s/Issues/";

    private final FortifyRequestHandler fortifyRequestHandler;
    private final BugTrackerSettings bugTrackerSettings;
    private final List<Integer> applicationIds;
    private final String issueUrl;

    private FortifyIssueManager(final FortifyClient client, final BugTrackerSettings bugTrackerSettings,
                                final List<Integer> applicationIds, final String issueUrl)
    {
        fortifyRequestHandler = new FortifyRequestHandler(client);
        this.bugTrackerSettings = bugTrackerSettings;
        this.applicationIds = applicationIds;
        this.issueUrl = issueUrl;
    }

    /**
     * Create bugs for Fortify issues.
     * @param configFile Configuration file for the Fortify issues manager
     */
    public static void manageIssues(final String configFile)
    {
        // Check that the required parameters have been specified
        if (Objects.isNull(configFile)) {
            throw new NullPointerException("Configuration file must be specified");
        }
        try
        {
            final FortifyIssueManagerConfiguration config = loadConfiguration(configFile);
            LOGGER.info("Managing Fortify issues ...");
            final FortifySettings fortifySettings = config.getFortifySettings();
            final FortifyClient client = new FortifyClient(
                                                        fortifySettings.getTenant() + "\\" + fortifySettings.getUsername(),
                                                        fortifySettings.getPassword(),
                                                        fortifySettings.getApiUrl(),
                                                        fortifySettings.getScope());
            client.authenticate();
            final FortifyIssueManager issueManager = new FortifyIssueManager(client,
                                                                             config.getBugTrackerSettings(),
                                                                             fortifySettings.getApplicationIds(),
                                                                             fortifySettings.getIssueUrl());
            issueManager.linkIssuesToBugTracker();
            LOGGER.info("Managing Fortify issues completed.");
        } catch (final IOException | ScriptNotFoundException | ScriptException e)
        {
            LOGGER.error("Error managing Fortify issues", e);
        }
    }

    private static FortifyIssueManagerConfiguration loadConfiguration(final String configFile) throws IOException
    {
        final Yaml yaml = new Yaml(new Constructor(FortifyIssueManagerConfiguration.class));
        try(final InputStream inputStream = FortifyIssueManager.class.getResourceAsStream(configFile))
        {
            final FortifyIssueManagerConfiguration config = yaml.load(inputStream);
            return config;
        }
    }

    private void linkIssuesToBugTracker() throws IOException, ScriptNotFoundException, ScriptException
    {
        // Get the list of configured Applications
        final FilterList filters = new FilterList();
        filters.addFilter("applicationId", Joiner.on('|').join(applicationIds));
        final String applicationFields = "applicationId,applicationName";
        LOGGER.info("Getting applications...");
        final List<Application> applications = fortifyRequestHandler.getApplications(filters, applicationFields);
        if(applications == null || applications.isEmpty())
        {
            LOGGER.info("No applications found.");
            return;
        }
        LOGGER.info("Got {} application(s).", applications.size());

        final JiraRequestHandler jiraReqHandler = new JiraRequestHandler(bugTrackerSettings);

        final Invocable bugPayloadScript = getBugPayloadScript();

        // For each application get Releases where sdlcStatusType is set to "Production"
        for(final Application application : applications)
        {
            final List<Release> releases =  getReleases(application.getApplicationId());
            if(releases == null || releases.isEmpty())
            {
                LOGGER.info("No releases in application {}.", application.getApplicationId());
                continue;
            }
            LOGGER.info("Got {} release(s).", releases.size());
            // For each Release get a list of all Vulnerabilities that have
            // severityString set to Critical or High AND bugSubmitted set to false
            for(final Release release : releases)
            {
                final List<Vulnerability> vulnerabilities = getVulnerabilities(release.getReleaseId());
                if(vulnerabilities == null || vulnerabilities.isEmpty())
                {
                    LOGGER.info("No vulnerabilities in release {} of application {}.",
                                release.getReleaseId(), application.getApplicationId());
                }
                else
                {
                    LOGGER.info("Got {} vulnerabilities.", vulnerabilities.size());
                    final Map<Category, List<Vulnerability>> sortedIssues = sortVulnerabilities(vulnerabilities);
                    // Create a bug in the bug tracker for each category of issues, update the vulnerability with the bugLink
                    createBugs(jiraReqHandler, application, release.getReleaseId(), sortedIssues, bugPayloadScript);
                }
            }
        }
    }

    private Invocable getBugPayloadScript() throws ScriptNotFoundException, ScriptException
    {
        final List<Script> scripts = bugTrackerSettings.getScripts();
        final Script getPayloadScript = scripts.stream()
                                               .filter(script -> script.getName().equals("getPayload.js"))
                                               .findFirst()
                                               .get();
        if(getPayloadScript == null)
        {
            throw new ScriptNotFoundException("Script getPayload.js not found.");
        }
        final ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
        engine.eval(getPayloadScript.getScript());
        final Invocable invocable = (Invocable) engine;
        return invocable;
    }

    /*
     * Get a list of 'production' releases for the application
     */
    private List<Release> getReleases(final int applicationId) throws IOException
    {
        LOGGER.info("Getting releases for application {}...", applicationId);
        final FilterList filters = new FilterList();
        filters.addFilter("applicationId", applicationId);
        filters.addFilter("sdlcStatusType", "Production");

        final String fields = "releaseId,releaseName,applicationId,applicationName,sdlcStatusType";

        final List<Release> releases = fortifyRequestHandler.getReleases(filters, fields);
        return releases;
    }

    private List<Vulnerability> getVulnerabilities(final int releaseId) throws IOException
    {
        LOGGER.info("Getting vulnerabilities for release {}...", releaseId);
        final FilterList filters = new FilterList();
        filters.addFilter("severityString", "Critical|High");
        filters.addFilter("bugSubmitted", false);

        final String fields = null;

        final List<Vulnerability> vulnerabilities = fortifyRequestHandler.getVulnerabilities(releaseId, filters, fields);
        return vulnerabilities;
    }

    private Map<Category, List<Vulnerability>> sortVulnerabilities(final List<Vulnerability> vulnerabilities)
    {
        // Sort the list of vulnerabilities based on their categories and severity.
        final Map<Category, List<Vulnerability>> sortedIssues = new HashMap<>();
        for(final Vulnerability vulnerability : vulnerabilities)
        {
            final Category category = new Category(vulnerability.getCategory(), vulnerability.getSeverity());
            if(!sortedIssues.containsKey(category))
            {
                sortedIssues.put(category, new ArrayList<Vulnerability>());
            }
            sortedIssues.get(category).add(vulnerability);
        }
        return sortedIssues;
    }

    private void createBugs(final JiraRequestHandler jiraReqHandler,
                            final Application application,
                            final int releaseId,
                            final Map<Category, List<Vulnerability>> sortedIssues,
                            final Invocable getPayLoadScript)
    {
        final String issueBaseUrl = String.format(FORTIFY_ISSUE_LINK_FORMAT, issueUrl, releaseId);
        try
        {
                final Set<Category> categories = sortedIssues.keySet();
                int counter = 1;
                for(final Category category : categories)
                {
                    LOGGER.info("Creating bugs for Application:{} Release:{} {}...",
                                application.getApplicationId(), releaseId, category);
                    LOGGER.info("-----------------------------------------");
                    final List<Vulnerability> vulnerabilities = sortedIssues.get(category);
                    final String bugDescription = category.getName().contains("Open Source")
                                                    ? getOpenSourceIssueDescription(issueBaseUrl, vulnerabilities)
                                                    : getIssueDescription(issueBaseUrl, vulnerabilities);
                    final String bugDetails = (String)getPayLoadScript.invokeFunction("getPayload",
                                                                      application.getApplicationId(),
                                                                      application.getApplicationName(),
                                                                      category.getSeverity(),
                                                                      category.getName(),
                                                                      bugDescription);
                    LOGGER.info("{} BUG-{} : {}", category.getName(), counter++, bugDetails);

                    try
                    {
                        final String bugLink = jiraReqHandler.createBug(bugDetails);
                        LOGGER.info("Updating vulnerabilities with bugLink {}...", bugLink);
                        final List<String> vulnerabilityIds = vulnerabilities.stream()
                                                                             .map(Vulnerability::getVulnId)
                                                                             .collect(Collectors.toList());
                        try
                        {
                            fortifyRequestHandler.updateVulnerability(releaseId, vulnerabilityIds, bugLink);
                        } catch (final IOException e)
                        {
                            LOGGER.error("Error updating vulnerability", e);
                        }
                    } catch (final BugTrackerException e)
                    {
                        LOGGER.error("Error creating bug", e);
                    }
                    LOGGER.info("-----------------------------------------");
                }

        } catch (final NoSuchMethodException | ScriptException e)
        {
            LOGGER.error("Error preparing issue payload", e);
        }
    }

    private String getIssueDescription(final String issueBaseUrl, final List<Vulnerability> vulnerabilities)
    {
        Collections.sort(vulnerabilities, Comparator.comparing(Vulnerability::getPrimaryLocation)
                                                    .thenComparing(Vulnerability::getId));

        final StringBuilder issues = new StringBuilder();
        issues.append("||Issue Id||Description||");
        for(final Vulnerability vulnerability : vulnerabilities)
        {
            issues.append("\n|[")
                  .append(vulnerability.getId())
                  .append("|")
                  .append(issueBaseUrl)
                  .append(vulnerability.getId())
                  .append("]|")
                  .append(vulnerability.getPrimaryLocation());
            if(vulnerability.getLineNumber() != null)
            {
                issues.append(" : ")
                      .append(vulnerability.getLineNumber());
            }
            issues.append("|");
        }
        return issues.toString();
    }

    private String getOpenSourceIssueDescription(final String issueBaseUrl, final List<Vulnerability> vulnerabilities)
    {
        vulnerabilities.sort(Comparator.comparing(Vulnerability::getPrimaryLocation));

        final StringBuilder issues = new StringBuilder();
        issues.append("||Issue Id||CVE ID||Component||");
        for(final Vulnerability vulnerability : vulnerabilities)
        {
            issues.append("\n|[")
                  .append(vulnerability.getId())
                  .append("|")
                  .append(issueBaseUrl)
                  .append(vulnerability.getId())
                  .append("]|")
                  .append(vulnerability.getCheckId())
                  .append("|")
                  .append(vulnerability.getPrimaryLocation());
            if(vulnerability.getLineNumber() != null)
            {
                issues.append(" : ")
                      .append(vulnerability.getLineNumber());
            }
            issues.append("|");
        }
        return issues.toString();
    }

}
