/*
 * Copyright 2020-2023 Open Text.
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

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import okhttp3.OkHttpClient;

final class FortifyClient
{
    private final static int CONNECTION_TIMEOUT = 30; // seconds
    private final static int WRITE_TIMEOUT = 600; // seconds
    private final static int READ_TIMEOUT = 600; // seconds

    private final String url;
    private final String authHeader;
    private final Map<String, String> proxySettings;
    private final OkHttpClient client;

    FortifyClient(
        final String url,
        final String token,
        final Map<String, String> proxySettings
    ) {
        this.url = url;
        this.authHeader = "FortifyToken " + token;
        this.proxySettings = proxySettings;
        this.client = createClient();
    }

    private OkHttpClient createClient() {
        final OkHttpClient.Builder baseClient = new OkHttpClient().newBuilder()
            .connectTimeout(CONNECTION_TIMEOUT, TimeUnit.SECONDS)
            .writeTimeout(WRITE_TIMEOUT, TimeUnit.SECONDS)
            .readTimeout(READ_TIMEOUT, TimeUnit.SECONDS);

        if (proxySettings != null && !proxySettings.isEmpty()) {
            final Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxySettings.get("host"),
                                                                                 Integer.valueOf(proxySettings.get("port"))));
            baseClient.proxy(proxy);
        }

        return baseClient.build();
    }

    public String getUrl() {
        return url;
    }

    public String getAuthHeader() {
        return authHeader;
    }

    public OkHttpClient getClient() {
        return client;
    }
}
