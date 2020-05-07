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
