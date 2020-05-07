@REM
@REM Copyright 2020 Micro Focus or one of its affiliates.
@REM
@REM The only warranties for products and services of Micro Focus and its
@REM affiliates and licensors ("Micro Focus") are set forth in the express
@REM warranty statements accompanying such products and services. Nothing
@REM herein should be construed as constituting an additional warranty.
@REM Micro Focus shall not be liable for technical or editorial errors or
@REM omissions contained herein. The information contained herein is subject
@REM to change without notice.
@REM
@REM Contains Confidential Information. Except as specifically indicated
@REM otherwise, a valid license is required for possession, use or copying.
@REM Consistent with FAR 12.211 and 12.212, Commercial Computer Software,
@REM Computer Software Documentation, and Technical Data for Commercial
@REM Items are licensed to the U.S. Government under vendor's standard
@REM commercial license.
@REM

@echo off
setlocal

:: Use the Maven exec plugin to get the class path
for /f "delims=" %%i in ('"mvn -q -f "%~dp0pom.xml" org.codehaus.mojo:exec-maven-plugin:1.5.0:exec -Dexec.executable=cmd -Dexec.args="/c echo %%classpath""') do set _PROJ_CLASSPATH=%%i

:: Execute the program
java -classpath %_PROJ_CLASSPATH% com.microfocus.sepg.fortify.issue.manager.cli.Program %*
