/*
 * Copyright 2020 Micro Focus or one of its affiliates.
 *
 * The only warranties for products and services of Micro Focus and its
 * affiliates and licensors ("Micro Focus") are set forth in the express
 * warranty statements accompanying such products and services. Nothing
 * herein should be construed as constituting an additional warranty.
 * Micro Focus shall not be liable for technical or editorial errors or
 * omissions contained herein. The information contained herein is subject
 * to change without notice.
 *
 * Contains Confidential Information. Except as specifically indicated
 * otherwise, a valid license is required for possession, use or copying.
 * Consistent with FAR 12.211 and 12.212, Commercial Computer Software,
 * Computer Software Documentation, and Technical Data for Commercial
 * Items are licensed to the U.S. Government under vendor's standard
 * commercial license.
 */
package com.microfocus.sepg.fortify.issue.tracker;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang.StringUtils;
import org.glassfish.jersey.internal.util.Base64;

import okhttp3.Authenticator;
import okhttp3.Credentials;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;

final class JiraClient
{
    private final static int CONNECTION_TIMEOUT = 30; // seconds
    private final static int WRITE_TIMEOUT = 600; // seconds
    private final static int READ_TIMEOUT = 600; // seconds

    private final String apiUrl;
    private final OkHttpClient client;

    private final String username;
    private final String password;

    private final int proxyPort;
    private final String proxyHost;

    private final String encodedAuth;

    JiraClient(final String username, final String password, final String apiUrl,
            final String proxyHost, final int proxyPort) {
        this.username = username;
        this.password = password;
        this.apiUrl = apiUrl;
        this.proxyHost = proxyHost;
        this.proxyPort = proxyPort;

        client = createClient();

        final String auth = username + ":" + password;
        encodedAuth = Base64.encodeAsString(auth.getBytes());
    }

    private OkHttpClient createClient() {
        final OkHttpClient.Builder baseClient = new OkHttpClient().newBuilder()
                .connectTimeout(CONNECTION_TIMEOUT, TimeUnit.SECONDS)
                .writeTimeout(WRITE_TIMEOUT, TimeUnit.SECONDS)
                .readTimeout(READ_TIMEOUT, TimeUnit.SECONDS);

        if(StringUtils.isNotEmpty(proxyHost))
        {
            final Authenticator proxyAuthenticator = new Authenticator() {
                @Override public Request authenticate(final Route route, final Response response) throws IOException {
                     final String credential = Credentials.basic(username, password);
                     return response.request().newBuilder()
                         .header("Proxy-Authorization", credential)
                         .build();
                }
              };

              baseClient.proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHost, proxyPort)))
                        .proxyAuthenticator(proxyAuthenticator);
        }
        return baseClient.build();
    }

    String getBasicAuthToken()
    {
        return encodedAuth;
    }

    String getApiUrl() {
        return apiUrl;
    }

    OkHttpClient getClient() {
        return client;
    }
}
