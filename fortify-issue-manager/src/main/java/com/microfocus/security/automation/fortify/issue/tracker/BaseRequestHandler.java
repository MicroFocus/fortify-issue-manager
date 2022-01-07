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
import com.microfocus.security.automation.fortify.issue.manager.BugTrackerSettings;
import com.microfocus.security.automation.fortify.issue.manager.ConfigurationException;
import com.microfocus.security.automation.fortify.issue.manager.ConfigurationManager;

import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.microfocus.security.automation.fortify.issue.manager.ConfigurationManager.getConfig;

public class BaseRequestHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(BaseRequestHandler.class);
    protected Map<String, String> proxySettings;
    protected List<String> configErrors;
    protected BugTrackerSettings bugTrackerSettings;

    BaseRequestHandler() throws ConfigurationException {
        loadConfiguration();
    }

    protected TrackerClient getClient()
    {
        return new TrackerClient(
                bugTrackerSettings.getUsername(),
                bugTrackerSettings.getPassword(),
                bugTrackerSettings.getApiUrl(),
                bugTrackerSettings.getProxySettings()
        );
    }

    protected String performPostRequest(
            final TrackerClient client,
            final String api,
            final String payload) throws IOException, BugTrackerException
    {
        final HttpUrl apiUrl = HttpUrl.parse(client.getApiUrl());
        if (apiUrl == null) {
            throw new BugTrackerException("Invalid url : " + api);
        }
        final String url = apiUrl.newBuilder().addPathSegments(api).build().toString();
        LOGGER.debug("Performing request POST {}", url);

        final RequestBody requestBody = RequestBody.create(MediaType.parse("application/json"), payload);

        final Request request = new Request.Builder()
                .url(url)
                .addHeader("Authorization", "Basic " + client.getBasicAuthToken())
                .post(requestBody)
                .build();

        final Response response = client.getClient().newCall(request).execute();
        final ResponseBody body = response.body();
        if (body == null) {
            throw new BugTrackerException("Response is null for : " + api);
        }

        // Read the result
        try (final InputStream responseStream = body.byteStream()) {
            final String responseContent = IOUtils.toString(responseStream, "utf-8");
            LOGGER.debug("performPostRequest response: {}", responseContent);
            return responseContent;
        }
    }

    private void loadConfiguration() throws ConfigurationException
    {
        proxySettings = ConfigurationManager.getProxySetting("HTTP_PROXY");
        configErrors = new ArrayList<>();

        // Get bug tracker settings
        final String bugTrackerUsername = getConfig("TRACKER_USERNAME", configErrors);
        final String bugTrackerPassword = getConfig("TRACKER_PASSWORD", configErrors);
        final String bugTrackerApiUrl = getConfig("TRACKER_API_URL", configErrors);

        if (!configErrors.isEmpty()) {
            throw new ConfigurationException("Invalid configuration " + configErrors);
        }

        bugTrackerSettings = new BugTrackerSettings(
            bugTrackerUsername,
            bugTrackerPassword,
            bugTrackerApiUrl,
            proxySettings
        );
    }
}
