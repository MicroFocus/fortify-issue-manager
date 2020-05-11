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

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.microfocus.security.automation.fortify.issue.manager.BugTrackerSettings;

import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public final class JiraRequestHandler
{
    private static final Logger LOGGER = LoggerFactory.getLogger(JiraRequestHandler.class);

    private final JiraClient client;
    final JsonParser parser;

    public JiraRequestHandler(final BugTrackerSettings bugTrackerSettings)
    {
        this.client = new JiraClient(
                                        bugTrackerSettings.getUsername(),
                                        bugTrackerSettings.getPassword(),
                                        bugTrackerSettings.getApiUrl(),
                                        bugTrackerSettings.getProxyHost(),
                                        bugTrackerSettings.getProxyPort()
                                    );
        this.parser = new JsonParser();
    }

    public String createBug(final String payload) throws BugTrackerException
    {
        try
        {
            final String issue = performPostRequest("rest/api/2/issue", payload);

            // Parse the Response
            final JsonObject response = parser.parse(issue).getAsJsonObject();
            if(response.has("key"))
            {
                final String bugLink = response.get("key").getAsString();
                return client.getApiUrl() + "/" + bugLink;
            }
            else
            {
                final String errors = response.get("errors").toString();
                throw new BugTrackerException(errors);
            }
        } catch (final IOException e)
        {
            throw new BugTrackerException(e);
        }
    }

    private String performPostRequest(final String api, final String payload) throws IOException
    {
        final HttpUrl.Builder builder = HttpUrl.parse(client.getApiUrl()).newBuilder().addPathSegments(api);
        final String url = builder.build().toString();
        LOGGER.info("Performing request POST {}", url);

        final RequestBody requestBody = RequestBody.create(MediaType.parse("application/json"), payload);

        final Request request = new Request.Builder()
                .url(url)
                .addHeader("Authorization", "Basic " + client.getBasicAuthToken())
                .post(requestBody)
                .build();

        final Response response = client.getClient().newCall(request).execute();

        // Read the results and close the response
        final String responseContent = IOUtils.toString(response.body().byteStream(), "utf-8");
        response.body().close();
        LOGGER.info("performPostRequest response: {}", responseContent);
        return responseContent;
    }
}
