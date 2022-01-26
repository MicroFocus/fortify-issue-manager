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
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.microfocus.security.automation.fortify.issue.manager.ConfigurationException;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.apache.commons.io.IOUtils;
import org.glassfish.jersey.internal.util.Base64;

import okhttp3.OkHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class JiraTrackerClient {
    private static final Logger LOGGER = LoggerFactory.getLogger(JiraTrackerClient.class);

    private final static int CONNECTION_TIMEOUT = 30; // seconds
    private final static int WRITE_TIMEOUT = 600; // seconds
    private final static int READ_TIMEOUT = 600; // seconds

    private final String apiUrl;
    private final OkHttpClient client;
    private final Map<String, String> proxySettings;

    private final String encodedAuth;

    private final static String REST_API_PATH = "/rest/api/2/issue";

    JiraTrackerClient(final BugTrackerSettings bugTrackerSettings) {
        this.apiUrl = bugTrackerSettings.getApiUrl();
        this.proxySettings = bugTrackerSettings.getProxySettings();

        client = createClient();

        final String auth = bugTrackerSettings.getUsername() + ":" + bugTrackerSettings.getPassword();
        encodedAuth = Base64.encodeAsString(auth.getBytes());
    }


    String performPostRequest(final String payload) throws IOException, BugTrackerException, ConfigurationException {
        final HttpUrl httpUrl = HttpUrl.parse(apiUrl);
        if (httpUrl == null) {
            throw new ConfigurationException("Invalid Jira configuration, invalid api url:" + apiUrl);
        }
        final String url = httpUrl.newBuilder().addPathSegments(REST_API_PATH).build().toString();
        LOGGER.debug("Performing request POST {}", url);

        final RequestBody requestBody = RequestBody.create(MediaType.parse("application/json"), payload);

        final Request request = new Request.Builder()
            .url(url)
            .addHeader("Authorization", "Basic " + encodedAuth)
            .post(requestBody)
            .build();

        final Response response = client.newCall(request).execute();
        if (!response.isSuccessful()) {
            throw new BugTrackerException("Failed to create issue for payload : " + payload);
        }

        // Read the result
        try (final InputStream responseStream = response.body().byteStream()) {
            final String responseContent = IOUtils.toString(responseStream, "utf-8");
            LOGGER.debug("performPostRequest response: {}", responseContent);
            return responseContent;
        }
    }

    OkHttpClient createClient() {
        final OkHttpClient.Builder baseClient = new OkHttpClient().newBuilder()
            .connectTimeout(CONNECTION_TIMEOUT, TimeUnit.SECONDS)
            .writeTimeout(WRITE_TIMEOUT, TimeUnit.SECONDS)
            .readTimeout(READ_TIMEOUT, TimeUnit.SECONDS);

        if (!proxySettings.isEmpty()) {
            final Proxy proxy = new Proxy(
                Proxy.Type.HTTP,
                new InetSocketAddress(
                    proxySettings.get("host"),
                    Integer.valueOf(proxySettings.get("port"))
                )
            );
            baseClient.proxy(proxy);
        }
        return baseClient.build();
    }
}
