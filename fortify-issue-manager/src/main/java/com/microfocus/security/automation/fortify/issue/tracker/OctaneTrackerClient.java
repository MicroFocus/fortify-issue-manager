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

import okhttp3.Cookie;
import okhttp3.CookieJar;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

final class OctaneTrackerClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(OctaneTrackerClient.class);

    private static final String URI_AUTHENTICATION = "/authentication/sign_in";
    private final static int CONNECTION_TIMEOUT = 30; // seconds
    private final static int WRITE_TIMEOUT = 600; // seconds
    private final static int READ_TIMEOUT = 600; // seconds

    private final OkHttpClient client;
    private final Map<String, String> proxySettings;
    private final BugTrackerSettings bugTrackerSettings;
    private final HashMap<String, List<Cookie>> cookieStore = new HashMap<>();

    OctaneTrackerClient(final BugTrackerSettings bugTrackerSettings) {
        this.bugTrackerSettings = bugTrackerSettings;
        this.proxySettings = bugTrackerSettings.getProxySettings();
        client = createClient();
    }

    String performPostRequest(
        final String defectUrl,
        final String payload) throws IOException, BugTrackerException {
        login();
        final HttpUrl apiUrl = HttpUrl.parse(bugTrackerSettings.getApiUrl());
        final String url = apiUrl.newBuilder().addPathSegments(defectUrl).build().toString();
        LOGGER.debug("Performing request POST {}", url);

        final RequestBody requestBody = RequestBody.create(MediaType.parse("application/json"), payload);

        final Request request = new Request.Builder()
            .url(url)
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

    private OkHttpClient createClient() {
        final OkHttpClient.Builder builder = new OkHttpClient.Builder()
            .cookieJar(new CookieJar() {
                @Override
                public void saveFromResponse(final HttpUrl httpUrl, final List<Cookie> list) {
                    cookieStore.put(httpUrl.host(), list);
                }

                @Override
                public List<Cookie> loadForRequest(final HttpUrl httpUrl) {
                    List<Cookie> cookies = cookieStore.get(httpUrl.host());
                    return cookies != null ? cookies : new ArrayList<>();
                }
            })
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
            builder.proxy(proxy);
        }
        return builder.build();
    }

    private void login() throws IOException {
        final HttpUrl url = HttpUrl.parse(bugTrackerSettings.getApiUrl() + URI_AUTHENTICATION);
        final String payload = "{\"client_id\":\""
            + bugTrackerSettings.getUsername()
            + "\",\"client_secret\":\""
            + bugTrackerSettings.getPassword() + "\"}";

        final RequestBody requestBody = RequestBody.create(MediaType.parse("application/json"), payload);

        final Request request = new Request.Builder()
            .url(url)
            .post(requestBody)
            .build();

        final Response response;
        response = client.newCall(request).execute();
        if (!response.isSuccessful()) {
            throw new OctaneLoginException("Authentication failed: code=" + response.code());
        }
    }

}
