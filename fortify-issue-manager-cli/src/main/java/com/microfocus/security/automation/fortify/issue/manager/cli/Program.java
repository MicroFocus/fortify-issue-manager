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
package com.microfocus.security.automation.fortify.issue.manager.cli;

import java.util.Objects;
import java.util.concurrent.Callable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.microfocus.security.automation.fortify.issue.manager.FortifyIssueManager;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "fortify-issue-manager")
public final class Program implements Callable<Integer>
{
    private static final Logger LOGGER = LoggerFactory.getLogger(Program.class);

    @Option(
        names = {"-d", "--dryRun"},
        paramLabel = "<dryRun>",
        defaultValue = "false",
        description = "If true, the tool lists the bug details but does not create them. Defaults to false."
    )
    private boolean dryRun;

    @Option(
        names = {"-s", "--scriptFile"},
        paramLabel = "<scriptFile>",
        description = "Script file with the `getPayload` function to create the bug details"
    )
    private String scriptFile;

    private Program()
    {
    }

    public static void main(final String[] args)
    {
        int exitCode = new CommandLine(new Program()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception
    {
        if (Objects.isNull(scriptFile)) {
            LOGGER.error("Script file with the `getPayload` function to create the bug details must be specified.");
            CommandLine.usage(new Program(), System.out);
        } else if (FortifyIssueManager.manageIssues(dryRun, scriptFile)) {
            return 0;
        } else {
            return -1;
        }
        return null;
    }
}
