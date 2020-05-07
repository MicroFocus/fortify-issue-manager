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
package com.microfocus.sepg.fortify.issue.manager.cli;

import java.util.Objects;
import java.util.concurrent.Callable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.microfocus.sepg.fortify.issue.manager.FortifyIssueManager;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "fortify-issue-manager")
public final class Program implements Callable<Void>
{
    private static final Logger LOGGER = LoggerFactory.getLogger(Program.class);

    @Option(
        names = {"-c", "--configFile"},
        paramLabel = "<configFile>",
        description = "Configuration file"
    )
    private String configFile;

    private Program()
    {
    }

    public static void main(final String[] args)
    {
        CommandLine.call(new Program(), args);
    }

    @Override
    public Void call() throws Exception
    {
        if (Objects.isNull(configFile)) {
            LOGGER.error("Configuration file must be specified.");
            CommandLine.usage(new Program(), System.out);
        } else {
            FortifyIssueManager.manageIssues(configFile);
        }
        return null;
    }

}
