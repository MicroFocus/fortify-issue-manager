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
package com.microfocus.sepg.fortify.issue.manager.test;

import org.junit.Ignore;
//import org.junit.Test;

import com.microfocus.sepg.fortify.issue.manager.FortifyIssueManager;

public class FortifyIssueManagerTest
{
    @Ignore
    public void testManageIssues() throws Exception
    {
        FortifyIssueManager.manageIssues("/fortifyIssueManagerConfig.yaml");
    }
}
