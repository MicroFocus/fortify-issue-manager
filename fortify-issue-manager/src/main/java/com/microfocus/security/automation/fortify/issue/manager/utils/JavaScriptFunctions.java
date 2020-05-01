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
package com.microfocus.security.automation.fortify.issue.manager.utils;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptException;

public final class JavaScriptFunctions
{
    private JavaScriptFunctions()
    {
    }

    /**
     * Invoke a function and return the stringified response.
     *
     * @param scriptEngine Script Engine
     * @param functionName Name of function to invoke
     * @param args Arguments for the function
     * @return The response as a JSON string
     * @throws NoSuchMethodException Throw if method with given name or matching argument types cannot be found.
     * @throws ScriptException Throw if an error occurs during invocation of the method.
     */
    public static String invokeFunction(final ScriptEngine scriptEngine, final String functionName, final Object... args)
        throws NoSuchMethodException, ScriptException
    {
        final Invocable invocableScript = (Invocable) scriptEngine;
        final Object responseObj = invocableScript.invokeFunction(functionName, args);

        final Object jsonObj = scriptEngine.get("JSON");
        final String response = (String) invocableScript.invokeMethod(jsonObj, "stringify", responseObj);
        return response;
    }
}
