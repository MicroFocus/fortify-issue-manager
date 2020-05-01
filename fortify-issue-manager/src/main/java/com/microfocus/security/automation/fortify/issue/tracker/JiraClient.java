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

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.glassfish.jersey.internal.util.Base64;

import okhttp3.OkHttpClient;

final class JiraClient
{
    private final static int CONNECTION_TIMEOUT = 30; // seconds
    private final static int WRITE_TIMEOUT = 600; // seconds
    private final static int READ_TIMEOUT = 600; // seconds

    private final String apiUrl;
    private final OkHttpClient client;
    private final Map<String, String> proxySettings;

    private final String encodedAuth;

    JiraClient(final String username, final String password, final String apiUrl, final Map<String, String> proxySettings)
    {
        this.apiUrl = apiUrl;
        this.proxySettings = proxySettings;

        client = createClient();

        final String auth = username + ":" + password;
        encodedAuth = Base64.encodeAsString(auth.getBytes());
    }

    private OkHttpClient createClient()
    {
        final OkHttpClient.Builder baseClient = new OkHttpClient().newBuilder()
            .connectTimeout(CONNECTION_TIMEOUT, TimeUnit.SECONDS)
            .writeTimeout(WRITE_TIMEOUT, TimeUnit.SECONDS)
            .readTimeout(READ_TIMEOUT, TimeUnit.SECONDS);

        if (!proxySettings.isEmpty()) {
            final Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxySettings.get("host"),
                                                                                 Integer.valueOf(proxySettings.get("port"))));
            baseClient.proxy(proxy);
        }
        return baseClient.build();
    }

    String getBasicAuthToken()
    {
        return encodedAuth;
    }

    String getApiUrl()
    {
        return apiUrl;
    }

    OkHttpClient getClient()
    {
        return client;
    }
}
