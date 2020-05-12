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
package com.microfocus.security.automation.fortify.issue.manager.test;

import static org.junit.Assert.assertTrue;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

import org.apache.commons.io.IOUtils;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.microfocus.security.automation.fortify.issue.manager.utils.JavaScriptFunctions;

public class JavaScriptFunctionsTest
{
    private static final Logger LOGGER = LoggerFactory.getLogger(JavaScriptFunctionsTest.class);

    @Test
    public void testInvokeFunction() throws Exception
    {
        LOGGER.info("Running testInvokeFunction...");
        final String description = "||Issue Id||CVE ID||Component||"
                                 + "\n|[103015915|CVE-2018-1270|com.acme.frontend.util:util-liquibase-installer@1.17.0-201|";
        final ScriptEngine engine = getScriptEngine("/getPayload.js");
        final String responseJson = JavaScriptFunctions.invokeFunction(engine, "getPayload",
                "Acme Front End",
                4,
                "Open Source",
                description);
        LOGGER.info("Response: {}", responseJson);

        final JsonParser parser = new JsonParser();
        final JsonObject response = parser.parse(responseJson).getAsJsonObject();
        final JsonObject fieldsNode = response.get("fields").getAsJsonObject();
        assertTrue("invokeFunction returned fields", fieldsNode != null);
        assertTrue("invokeFunction returned project", fieldsNode.has("project"));
        assertTrue("invokeFunction returned issuetype", fieldsNode.has("issuetype"));
        assertTrue("invokeFunction returned summary", fieldsNode.has("summary"));
        assertTrue("invokeFunction returned description", fieldsNode.has("description"));
        assertTrue("invokeFunction returned priority", fieldsNode.has("priority"));
    }

    private ScriptEngine getScriptEngine(final String scriptFile) throws FileNotFoundException, IOException, ScriptException
    {
        LOGGER.info("Loding script from {}", scriptFile);
        try(final InputStream inputStream = JavaScriptFunctionsTest.class.getResourceAsStream(scriptFile))
        {
            final String script = IOUtils.toString(inputStream, "utf-8");
            final ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
            engine.eval(script);
            return engine;
        }
    }
}
