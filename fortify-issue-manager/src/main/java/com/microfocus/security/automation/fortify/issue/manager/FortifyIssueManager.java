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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Joiner;
import com.microfocus.security.automation.fortify.issue.manager.FortifyClient.GrantType;
import com.microfocus.security.automation.fortify.issue.manager.models.Application;
import com.microfocus.security.automation.fortify.issue.manager.models.Category;
import com.microfocus.security.automation.fortify.issue.manager.models.Release;
import com.microfocus.security.automation.fortify.issue.manager.models.Vulnerability;
import com.microfocus.security.automation.fortify.issue.manager.utils.JavaScriptFunctions;
import com.microfocus.security.automation.fortify.issue.tracker.JiraRequestHandler;

public final class FortifyIssueManager
{
    private static final Logger LOGGER = LoggerFactory.getLogger(FortifyIssueManager.class);
    private final String FORTIFY_ISSUE_LINK_FORMAT = "%s/Releases/%s/Issues/";

    private final FortifyRequestHandler fortifyRequestHandler;
    private final BugTracker bugTracker;
    private final String[] applicationIds;
    private final String issueUrl;
    private static boolean hasErrors;

    private FortifyIssueManager(
        final FortifyClient client,
        final BugTrackerSettings bugTrackerSettings,
        final String[] applicationIds,
        final String issueUrl
    )
    {
        this.fortifyRequestHandler = new FortifyRequestHandler(client);
        this.bugTracker = new JiraRequestHandler(bugTrackerSettings);
        this.applicationIds = applicationIds;
        this.issueUrl = issueUrl;
    }

    /**
     * Create bugs for Fortify issues.
     *
     * @param scriptFile Script file to create the bug payload
     * @return true if there were no errors when managing issues
     */
    public static boolean manageIssues(final String scriptFile)
    {
        // Check that the required parameters have been specified
        if (Objects.isNull(scriptFile)) {
            throw new NullPointerException("Script file must be specified");
        }
        try {
            final FortifyIssueManagerConfiguration config = loadConfiguration();
            LOGGER.info("Managing Fortify issues ...");
            final FortifySettings fortifySettings = config.getFortifySettings();
            final BugTrackerSettings bugTrackerSettings = config.getBugTrackerSettings();
            final FortifyClient client = new FortifyClient(
                fortifySettings.getGrantType(),
                fortifySettings.getId(),
                fortifySettings.getSecret(),
                fortifySettings.getApiUrl(),
                fortifySettings.getScope(),
                fortifySettings.getProxySettings());
            client.authenticate();
            final FortifyIssueManager issueManager = new FortifyIssueManager(
                client, bugTrackerSettings, fortifySettings.getApplicationIds(), fortifySettings.getIssueUrl());
            issueManager.linkIssuesToBugTracker(scriptFile);
        } catch (final IOException | ScriptNotFoundException | ScriptException | FortifyAuthenticationException |
                       FortifyRequestException | NoSuchMethodException | ConfigurationException e) {
            LOGGER.error("Error managing Fortify issues", e);
            hasErrors = true;
        }
        LOGGER.info("Managing Fortify issues completed with {}", hasErrors ? "errors." : "no errors.");
        return !hasErrors;
    }

    private static FortifyIssueManagerConfiguration loadConfiguration() throws ConfigurationException
    {
        final Map<String, String> proxySettings = getProxySetting("HTTP_PROXY");
        final List<String> configErrors = new ArrayList<>();

        // Get Fortify settings
        final String grantType = System.getenv("FORTIFY_GRANT_TYPE");
        final String fortifyId;
        final GrantType fortifyGrantType;
        final String fortifySecret;

        if (GrantType.CLIENT_CREDENTIALS.name().equalsIgnoreCase(grantType)) {
            fortifyGrantType = GrantType.CLIENT_CREDENTIALS;
            fortifyId = getConfig("FORTIFY_CLIENT_ID", configErrors);
            fortifySecret = getConfig("FORTIFY_CLIENT_SECRET", configErrors);
        } else if (GrantType.PASSWORD.name().equalsIgnoreCase(grantType)) {
            fortifyGrantType = GrantType.PASSWORD;
            fortifyId = getConfig("FORTIFY_TENANT", configErrors) + "\\" + getConfig("FORTIFY_USERNAME", configErrors);
            fortifySecret = getConfig("FORTIFY_PASSWORD", configErrors);
        } else {
            throw new ConfigurationException("Invalid Fortify grant type. Set FORTIFY_GRANT_TYPE to 'client_credentials' or 'password'");
        }

        final String fortifyScope = getConfig("FORTIFY_SCOPE", configErrors);
        final String fortifyApiUrl = getConfig("FORTIFY_API_URL", configErrors);
        final String fortifyIssueUrl = getConfig("FORTIFY_ISSUE_URL", configErrors);
        final String fortifyApplicationIds[] = System.getenv("FORTIFY_APPLICATION_IDS") == null
            ? null
            : System.getenv("FORTIFY_APPLICATION_IDS").split(",");

        // Get bug tracker settings
        final String bugTrackerUsername = getConfig("JIRA_USERNAME", configErrors);
        final String bugTrackerPassword = getConfig("JIRA_PASSWORD", configErrors);
        final String bugTrackerApiUrl = getConfig("JIRA_API_URL", configErrors);

        if (!configErrors.isEmpty()) {
            throw new ConfigurationException("Invalid configuration " + configErrors);
        }

        final FortifySettings fortifySettings = new FortifySettings(
            fortifyGrantType, fortifyId, fortifySecret, fortifyScope,
            fortifyApiUrl, fortifyIssueUrl, proxySettings, fortifyApplicationIds);

        final BugTrackerSettings bugTrackerSettings = new BugTrackerSettings(
            bugTrackerUsername, bugTrackerPassword, bugTrackerApiUrl, proxySettings);

        final FortifyIssueManagerConfiguration config = new FortifyIssueManagerConfiguration(fortifySettings, bugTrackerSettings);
        return config;
    }

    private static String getConfig(final String configName, final List<String> errorConfigs)
    {
        final String configValue = System.getenv(configName);
        if (StringUtils.isEmpty(configValue)) {
            errorConfigs.add(configName);
        }
        return configValue;
    }

    private void linkIssuesToBugTracker(final String scriptFile)
        throws IOException, ScriptNotFoundException, ScriptException, FortifyAuthenticationException, FortifyRequestException, NoSuchMethodException
    {
        if (this.applicationIds == null || this.applicationIds.length == 0) {
            LOGGER.info("No application ids configured.");
            return;
        }

        // Get the list of configured Applications
        final FilterList filters = new FilterList();
        filters.addFilter("applicationId", Joiner.on('|').join(this.applicationIds));
        final String applicationFields = "applicationId,applicationName";
        LOGGER.info("Getting applications...");
        final List<Application> applications = this.fortifyRequestHandler.getApplications(filters, applicationFields);
        if (applications == null || applications.isEmpty()) {
            LOGGER.info("No applications found.");
            return;
        }
        LOGGER.info("Got {} application(s).", applications.size());

        final ScriptEngine bugPayloadScript = getBugPayloadScript(scriptFile);

        // For each application get Releases where sdlcStatusType is set to "Production"
        for (final Application application : applications) {
            LOGGER.info("---- Managing issues in application {} ----", application.getApplicationName());
            final List<Release> releases = getReleases(application.getApplicationId());
            if (releases == null || releases.isEmpty()) {
                LOGGER.info("No releases in application {}.", application.getApplicationId());
                continue;
            }
            LOGGER.info("Got {} release(s).", releases.size());
            // For each Release get a list of all Vulnerabilities that have
            // severityString set to Critical or High AND bugSubmitted set to false
            for (final Release release : releases) {
                final List<Vulnerability> vulnerabilities = getVulnerabilities(release.getReleaseId());
                if (vulnerabilities == null || vulnerabilities.isEmpty()) {
                    LOGGER.info("No vulnerabilities in release {} of application {}.",
                                release.getReleaseId(), application.getApplicationId());
                } else {
                    LOGGER.info("Got {} vulnerabilities.", vulnerabilities.size());
                    final Map<Category, List<Vulnerability>> sortedIssues = sortVulnerabilities(vulnerabilities);
                    // Create a bug in the bug tracker for each category of issues, update the vulnerability with the bugLink
                    createBugs(application, release.getReleaseId(), sortedIssues, bugPayloadScript);
                }
            }
            LOGGER.info("---- Managing issues in application {} completed. ----", application.getApplicationName());
        }
    }

    private ScriptEngine getBugPayloadScript(final String scriptFile)
        throws ScriptNotFoundException, ScriptException, FileNotFoundException, IOException
    {
        LOGGER.info("Loding script from {}", scriptFile);
        try (final InputStream inputStream = new FileInputStream(scriptFile)) {
            final String getPayloadScript = IOUtils.toString(inputStream, "utf-8");
            if (StringUtils.isEmpty(getPayloadScript)) {
                throw new ScriptNotFoundException("Script getPayload not found.");
            }
            final ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
            engine.eval(getPayloadScript);
            return engine;
        }
    }

    /*
     * Get a list of 'production' releases for the application
     */
    private List<Release> getReleases(final int applicationId)
        throws IOException, FortifyAuthenticationException, FortifyRequestException
    {
        LOGGER.info("Getting releases for application {}...", applicationId);
        final FilterList filters = new FilterList();
        filters.addFilter("applicationId", applicationId);
        filters.addFilter("sdlcStatusType", "Production");

        final String fields = "releaseId,releaseName,applicationId,applicationName,sdlcStatusType";

        final List<Release> releases = this.fortifyRequestHandler.getReleases(filters, fields);
        return releases;
    }

    private List<Vulnerability> getVulnerabilities(final int releaseId)
        throws IOException, FortifyAuthenticationException, FortifyRequestException
    {
        LOGGER.info("Getting vulnerabilities for release {}...", releaseId);
        final FilterList filters = new FilterList();
        filters.addFilter("severityString", "Critical|High");
        filters.addFilter("bugSubmitted", false);

        final String fields = null;
        final List<Vulnerability> vulnerabilities = this.fortifyRequestHandler.getVulnerabilities(releaseId, filters, fields);
        return vulnerabilities;
    }

    private Map<Category, List<Vulnerability>> sortVulnerabilities(final List<Vulnerability> vulnerabilities)
    {
        // Sort the list of vulnerabilities based on their categories and severity.
        final Map<Category, List<Vulnerability>> sortedIssues = new HashMap<>();
        for (final Vulnerability vulnerability : vulnerabilities) {
            final Category category = new Category(vulnerability.getCategory(), vulnerability.getSeverity());
            if (!sortedIssues.containsKey(category)) {
                sortedIssues.put(category, new ArrayList<>());
            }
            sortedIssues.get(category).add(vulnerability);
        }
        return sortedIssues;
    }

    private void createBugs(final Application application,
                            final int releaseId,
                            final Map<Category, List<Vulnerability>> sortedIssues,
                            final ScriptEngine getPayLoadScript) throws FortifyRequestException, NoSuchMethodException, ScriptException
    {
        final String issueBaseUrl = String.format(FORTIFY_ISSUE_LINK_FORMAT, issueUrl, releaseId);

        final Set<Category> categories = sortedIssues.keySet();
        int counter = 1;
        for (final Category category : categories) {
            LOGGER.info("Creating bugs for Application:{} Release:{} {}...",
                        application.getApplicationId(), releaseId, category);
            LOGGER.debug("-----------------------------------------");
            final List<Vulnerability> vulnerabilities = sortedIssues.get(category);
            final String bugDescription = category.getName().contains("Open Source")
                ? getOpenSourceIssueDescription(issueBaseUrl, vulnerabilities)
                : getIssueDescription(issueBaseUrl, vulnerabilities);

            final String bugDetails = JavaScriptFunctions.invokeFunction(getPayLoadScript, "getPayload",
                                                                         application.getApplicationName(),
                                                                         category.getSeverity(),
                                                                         category.getName(),
                                                                         bugDescription);

            LOGGER.debug("{} BUG-{} : {}", category.getName(), counter++, bugDetails);

            try {
                final String bugLink = this.bugTracker.createBug(bugDetails);
                final List<String> vulnerabilityIds = vulnerabilities.stream()
                    .map(Vulnerability::getVulnId)
                    .collect(Collectors.toList());
                try {
                    this.fortifyRequestHandler.updateVulnerability(releaseId, vulnerabilityIds, bugLink);
                    LOGGER.info("Updated {} vulnerabilities with bugLink {}.", category.getName(), bugLink);
                } catch (final IOException e) {
                    LOGGER.error("Error updating vulnerability", e);
                }
            } catch (final BugTrackerException e) {
                LOGGER.error("Error creating bug", e);
                hasErrors = true;
            }
            LOGGER.debug("-----------------------------------------");
        }
    }

    private String getIssueDescription(final String issueBaseUrl, final List<Vulnerability> vulnerabilities)
    {
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

    private String getOpenSourceIssueDescription(final String issueBaseUrl, final List<Vulnerability> vulnerabilities)
    {
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

    private static Map<String, String> getProxySetting(final String proxyEnvVariable)
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
}
