#!/usr/bin/env python3

import os
import re
import sys

###############################################################################
# 1. Define the Classifier Rules
###############################################################################

# Each rule has the following structure (simplified):
# {
#   "EnumerationScope": "FileEnumeration" or "ContentsEnumeration",
#   "RuleName": "<string>",
#   "MatchAction": "<Discard|Continue|Relay|CheckForKeys>",
#   "Description": "<string>",
#   "MatchLocation": "FileExtension"|"FileName"|"FilePath"|"FileContentAsString",
#   "WordListType": "Exact"|"Regex"|"Contains"|"EndsWith",
#   "WordList": [ ... ],
#   "RelayTargets": [ ... ] (only valid if MatchAction=Relay),
#   "Triage": "<Green|Yellow|Red|Black>",  # or omitted
# }
#
# The script focuses on the essential aspects:
#   - FileEnumeration => Check file path/extension/name
#   - ContentsEnumeration => We do text-based pattern checks
#   - If "Discard", skip further checks. If "Relay", gather the matching
#     "RelayTargets" => those are typically "ContentsEnumeration" rules to run
#     on the file content.

RULES = [

    # -------------------------------------------------------------------------
    # KeepCmdCredentials
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "ContentsEnumeration",
        "RuleName": "KeepCmdCredentials",
        "MatchAction": "Continue",
        "Description": "Files with contents matching these regexen are very interesting.",
        "MatchLocation": "FileContentAsString",
        "WordListType": "Regex",
        "WordList": [
            r"passwo?r?d\s*=\s*['\"][^'\"]....",
            r"schtasks.{1,300}(/rp\s|/p\s)",
            r"net user ",
            r"psexec .{0,100} -p ",
            r"net use .{0,300} /user:",
            r"cmdkey "
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # RelayCmdByExtension
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "RelayCmdByExtension",
        "MatchAction": "Relay",
        "RelayTargets": [
            "KeepCmdCredentials",
            "KeepAwsKeysInCode",
            "KeepInlinePrivateKey",
            "KeepPassOrKeyInCode",
            "KeepSlackTokensInCode",
            "KeepSqlAccountCreation"
        ],
        "Description": "Files with .bat or .cmd -> content checks for interesting strings",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [
            r"\.bat",
            r"\.cmd"
        ],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # KeepSlackTokensInCode
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "ContentsEnumeration",
        "RuleName": "KeepSlackTokensInCode",
        "MatchAction": "Continue",
        "Description": "Slack tokens / webhooks in file content",
        "MatchLocation": "FileContentAsString",
        "WordListType": "Regex",
        "WordList": [
            r"(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
            r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # KeepSqlAccountCreation
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "ContentsEnumeration",
        "RuleName": "KeepSqlAccountCreation",
        "MatchAction": "Continue",
        "Description": "SQL user creation lines",
        "MatchLocation": "FileContentAsString",
        "WordListType": "Regex",
        "WordList": [
            r"CREATE (USER|LOGIN) .{0,200} (IDENTIFIED BY|WITH PASSWORD)"
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # RelayPythonByExtension
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "RelayPythonByExtension",
        "MatchAction": "Relay",
        "RelayTargets": [
            "KeepPyDbConnStrings",
            "KeepAwsKeysInCode",
            "KeepInlinePrivateKey",
            "KeepPassOrKeyInCode",
            "KeepSlackTokensInCode",
            "KeepSqlAccountCreation",
            "KeepDbConnStringPw"
        ],
        "Description": "Python files -> check for python db connections, credentials, etc.",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [r"\.py"],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # KeepPyDbConnStrings
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "ContentsEnumeration",
        "RuleName": "KeepPyDbConnStrings",
        "MatchAction": "Continue",
        "Description": "Python DB connection strings",
        "MatchLocation": "FileContentAsString",
        "WordListType": "Regex",
        "WordList": [
            r"mysql\.connector\.connect\(",
            r"psycopg2\.connect\("
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # KeepS3UriPrefixInCode
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "ContentsEnumeration",
        "RuleName": "KeepS3UriPrefixInCode",
        "MatchAction": "Continue",
        "Description": "AWS S3 or Hadoop S3A URIs",
        "MatchLocation": "FileContentAsString",
        "WordListType": "Regex",
        "WordList": [
            r"s3[a]?:\/\/[a-zA-Z0-9\-\+/]{2,16}"
        ],
        "Triage": "Yellow",
    },

    # -------------------------------------------------------------------------
    # KeepPerlDbConnStrings
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "ContentsEnumeration",
        "RuleName": "KeepPerlDbConnStrings",
        "MatchAction": "Continue",
        "Description": "Perl DB connection strings",
        "MatchLocation": "FileContentAsString",
        "WordListType": "Regex",
        "WordList": [
            r"DBI\-?>connect\("
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # RelayPerlByExtension
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "RelayPerlByExtension",
        "MatchAction": "Relay",
        "RelayTargets": [
            "KeepPerlDbConnStrings",
            "KeepAwsKeysInCode",
            "KeepInlinePrivateKey",
            "KeepPassOrKeyInCode",
            "KeepSlackTokensInCode",
            "KeepSqlAccountCreation",
            "KeepDbConnStringPw"
        ],
        "Description": "Perl files -> check for credentials",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [r"\.pl"],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # KeepAwsKeysInCode
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "ContentsEnumeration",
        "RuleName": "KeepAwsKeysInCode",
        "MatchAction": "Continue",
        "Description": "AWS keys in file content",
        "MatchLocation": "FileContentAsString",
        "WordListType": "Regex",
        "WordList": [
            r"aws[_\-\.]?key",
            r"(\s|\'|\"|\^|=)(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z2-7]{12,16}(\s|\'|\"|$)"
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # RelayJavaByExtension
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "RelayJavaByExtension",
        "MatchAction": "Relay",
        "RelayTargets": [
            "KeepJavaDbConnStrings",
            "KeepAwsKeysInCode",
            "KeepInlinePrivateKey",
            "KeepPassOrKeyInCode",
            "KeepSlackTokensInCode",
            "KeepSqlAccountCreation",
            "KeepDbConnStringPw"
        ],
        "Description": "Java/ColdFusion files -> check DB connections, credentials, etc.",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [r"\.jsp", r"\.do", r"\.java", r"\.cfm"],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # KeepJavaDbConnStrings
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "ContentsEnumeration",
        "RuleName": "KeepJavaDbConnStrings",
        "MatchAction": "Continue",
        "Description": "Java DB connections",
        "MatchLocation": "FileContentAsString",
        "WordListType": "Regex",
        "WordList": [
            r"\.getConnection\(\"jdbc:",
            r"passwo?r?d\s*=\s*['\"][^'\"]...."
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # KeepPhpByName
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepPhpByName",
        "MatchAction": "Continue",
        "Description": "Specific interesting PHP file names",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [r"LocalSettings\.php"],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # RelayPhpByExtension
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "RelayPhpByExtension",
        "MatchAction": "Relay",
        "RelayTargets": [
            "KeepPhpDbConnStrings",
            "KeepAwsKeysInCode",
            "KeepInlinePrivateKey",
            "KeepPassOrKeyInCode",
            "KeepSlackTokensInCode",
            "KeepSqlAccountCreation",
            "KeepDbConnStringPw"
        ],
        "Description": "PHP files -> check DB connections, credentials, etc.",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [
            r"\.php",
            r"\.phtml",
            r"\.inc",
            r"\.php3",
            r"\.php5",
            r"\.php7"
        ],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # KeepPhpDbConnStrings
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "ContentsEnumeration",
        "RuleName": "KeepPhpDbConnStrings",
        "MatchAction": "Continue",
        "Description": "PHP DB connections",
        "MatchLocation": "FileContentAsString",
        "WordListType": "Regex",
        "WordList": [
            r"mysql_connect\s*\(.*\$.*\)",
            r"mysql_pconnect\s*\(.*\$.*\)",
            r"mysql_change_user\s*\(.*\$.*\)",
            r"pg_connect\s*\(.*\$.*\)",
            r"pg_pconnect\s*\(.*\$.*\)"
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # RelayPsByExtension
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "RelayPsByExtension",
        "MatchAction": "Relay",
        "RelayTargets": [
            "KeepPsCredentials",
            "KeepCmdCredentials",
            "KeepAwsKeysInCode",
            "KeepInlinePrivateKey",
            "KeepPassOrKeyInCode",
            "KeepSlackTokensInCode",
            "KeepSqlAccountCreation",
            "KeepDbConnStringPw"
        ],
        "Description": "PowerShell files -> check for credentials, net-use, etc.",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [r"\.psd1", r"\.psm1", r"\.ps1"],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # KeepPsCredentials
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "ContentsEnumeration",
        "RuleName": "KeepPsCredentials",
        "MatchAction": "Continue",
        "Description": "PowerShell credential patterns",
        "MatchLocation": "FileContentAsString",
        "WordListType": "Regex",
        "WordList": [
            r"-SecureString",
            r"-AsPlainText",
            r"\[Net.NetworkCredential\]::new\("
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # KeepPSHistoryByName
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepPSHistoryByName",
        "MatchAction": "Relay",
        "RelayTargets": [
            "KeepPsCredentials",
            "KeepCmdCredentials",
            "KeepAwsKeysInCode",
            "KeepInlinePrivateKey",
            "KeepPassOrKeyInCode",
            "KeepSlackTokensInCode",
            "KeepSqlAccountCreation",
            "KeepDbConnStringPw"
        ],
        "Description": "PowerShell history files -> check if anything interesting is stored",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [
            r"ConsoleHost_history\.txt",
            r"Visual Studio Code Host_history\.txt"
        ],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # KeepDbConnStringPw
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "ContentsEnumeration",
        "RuleName": "KeepDbConnStringPw",
        "MatchAction": "Continue",
        "Description": "Generic DB Connection string with 'password'",
        "MatchLocation": "FileContentAsString",
        "WordListType": "Regex",
        "WordList": [
            r"connectionstring.{1,200}passw"
        ],
        "Triage": "Yellow",
    },

    # -------------------------------------------------------------------------
    # RelayShellScriptByExtension
    # (Here we’re not implementing any “KeepShellScriptCredentials” rule specifically, so we just link existing ones)
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "RelayShellScriptByExtension",
        "MatchAction": "Relay",
        "RelayTargets": [
            # "KeepShellScriptCredentials", # commented out in your snippet
            "KeepAwsKeysInCode",
            "KeepInlinePrivateKey",
            "KeepPassOrKeyInCode",
            "KeepSlackTokensInCode",
            "KeepSqlAccountCreation"
        ],
        "Description": "Shell scripts and rc files -> check for secrets",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [
            r"\.netrc",
            r"\.exports",
            r"\.functions",
            r"\.extra",
            r"\.npmrc",
            r"\.env",
            r"\.bashrc",
            r"\.profile",
            r"\.zshrc",
            r"\.bash_history",
            r"\.zsh_history",
            r"\.sh_history",
            r"zhistory",
            r"\.irb_history"
        ],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # RelayCSharpByExtension
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "RelayCSharpByExtension",
        "MatchAction": "Relay",
        "RelayTargets": [
            "KeepCSharpDbConnStringsYellow",
            "KeepCSharpDbConnStringsRed",
            "KeepCSharpViewstateKeys",
            "KeepAwsKeysInCode",
            "KeepInlinePrivateKey",
            "KeepPassOrKeyInCode",
            "KeepSlackTokensInCode",
            "KeepSqlAccountCreation",
            "KeepDbConnStringPw",
            "KeepCSharpDbConnStringsRed",
            "KeepCSharpDbConnStringsYellow"
        ],
        "Description": "C# or ASP.NET files -> check for credentials, connection strings, viewstate keys.",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [
            r"\.aspx",
            r"\.ashx",
            r"\.asmx",
            r"\.asp",
            r"\.cshtml",
            r"\.cs",
            r"\.ascx",
            r"\.config"
        ],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # KeepCSharpViewstateKeys
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "ContentsEnumeration",
        "RuleName": "KeepCSharpViewstateKeys",
        "MatchAction": "Continue",
        "Description": "ASP.NET MachineKeys in config",
        "MatchLocation": "FileContentAsString",
        "WordListType": "Regex",
        "WordList": [
            r"validationkey\s*=\s*['\"][^'\"]....",
            r"decryptionkey\s*=\s*['\"][^'\"]...."
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # KeepCSharpDbConnStringsYellow
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "ContentsEnumeration",
        "RuleName": "KeepCSharpDbConnStringsYellow",
        "MatchAction": "Continue",
        "Description": "Integrated Security DB connection strings (less severe).",
        "MatchLocation": "FileContentAsString",
        "WordListType": "Regex",
        "WordList": [
            r"Data Source=.+Integrated Security=(SSPI|true)",
            r"Integrated Security=(SSPI|true);.*Data Source=.+"
        ],
        "Triage": "Yellow",
    },

    # -------------------------------------------------------------------------
    # KeepCSharpDbConnStringsRed
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "ContentsEnumeration",
        "RuleName": "KeepCSharpDbConnStringsRed",
        "MatchAction": "Continue",
        "Description": "SQL connection strings with a password.",
        "MatchLocation": "FileContentAsString",
        "WordListType": "Regex",
        "WordList": [
            r"Data Source=.+(;|)Password=.+(;|)",
            r"Password=.+(;|)Data Source=.+(;|)"
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # KeepConfigByName
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepConfigByName",
        "MatchAction": "Continue",
        "Description": "Certain config files by exact name",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [
            r"\.htpasswd",
            r"accounts\.v4"
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # RelayConfigByExtension
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "RelayConfigByExtension",
        "MatchAction": "Relay",
        "RelayTargets": [
            "KeepAwsKeysInCode",
            "KeepInlinePrivateKey",
            "KeepPassOrKeyInCode",
            "KeepSlackTokensInCode",
            "KeepSqlAccountCreation",
            "KeepDbConnStringPw"
        ],
        "Description": "Generic config files -> check for secrets",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [
            r"\.yaml",
            r"\.yml",
            r"\.toml",
            r"\.xml",
            r"\.json",
            r"\.config",
            r"\.ini",
            r"\.inf",
            r"\.cnf",
            r"\.conf",
            r"\.properties",
            r"\.env",
            r"\.dist",
            r"\.txt",
            r"\.sql",
            r"\.log",
            r"\.sqlite",
            r"\.sqlite3",
            r"\.fdb",
            r"\.tfvars"
        ],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # KeepPassOrKeyInCode
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "ContentsEnumeration",
        "RuleName": "KeepPassOrKeyInCode",
        "MatchAction": "Continue",
        "Description": "Generic pattern: password= or apiKey= etc.",
        "MatchLocation": "FileContentAsString",
        "WordListType": "Regex",
        "WordList": [
            r"passw?o?r?d\s*=\s*['\"][^'\"]....",
            r"api[Kk]ey\s*=\s*['\"][^'\"]....",
            r"passw?o?r?d?>\s*[^\s<]+\s*<",
            r"passw?o?r?d?>.{3,2000}</pass",
            r"[\s]+-passw?o?r?d?",
            r"api[kK]ey>\s*[^\s<]+\s*<",
            r"[_\-\.]oauth\s*=\s*['\"][^'\"]....",
            r"client_secret\s*=*\s*",
            r"<ExtendedMatchKey>ClientAuth",
            r"GIUserPassword"
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # KeepInlinePrivateKey
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "ContentsEnumeration",
        "RuleName": "KeepInlinePrivateKey",
        "MatchAction": "Continue",
        "Description": "Inline private key markers",
        "MatchLocation": "FileContentAsString",
        "WordListType": "Regex",
        "WordList": [
            r"-----BEGIN( RSA| OPENSSH| DSA| EC| PGP)? PRIVATE KEY( BLOCK)?-----"
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # RelayJsByExtension
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "RelayJsByExtension",
        "MatchAction": "Relay",
        "RelayTargets": [
            "KeepAwsKeysInCode",
            "KeepInlinePrivateKey",
            "KeepPassOrKeyInCode",
            "KeepSlackTokensInCode",
            "KeepSqlAccountCreation",
            "KeepDbConnStringPw"
        ],
        "Description": "JS/TS files -> check for secrets",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [
            r"\.js",
            r"\.cjs",
            r"\.mjs",
            r"\.cs",    # caution: also in csharp extension above, but included in your snippet
            r"\.ts",
            r"\.tsx",
            r"\.ls",
            r"\.es6",
            r"\.es"
        ],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # RelayVBScriptByExtension
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "RelayVBScriptByExtension",
        "MatchAction": "Relay",
        "RelayTargets": [
            "KeepCmdCredentials",
            "KeepAwsKeysInCode",
            "KeepInlinePrivateKey",
            "KeepPassOrKeyInCode",
            "KeepSlackTokensInCode",
            "KeepSqlAccountCreation",
            "KeepDbConnStringPw",
            "KeepCSharpDbConnStringsRed",
            "KeepCSharpDbConnStringsYellow"
        ],
        "Description": "VBScript/Classic ASP -> check for net use, pass=, etc.",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [
            r"\.vbs",
            r"\.vbe",
            r"\.wsf",
            r"\.wsc",
            r"\.asp",
            r"\.hta"
        ],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # KeepRubyByName
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepRubyByName",
        "MatchAction": "Continue",
        "Description": "Certain Ruby config files",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [
            r"database\.yml",
            r"\.secret_token\.rb",
            r"knife\.rb",
            r"carrierwave\.rb",
            r"omniauth\.rb"
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # KeepRubyDbConnStrings
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "ContentsEnumeration",
        "RuleName": "KeepRubyDbConnStrings",
        "MatchAction": "Continue",
        "Description": "Ruby DBI connect calls",
        "MatchLocation": "FileContentAsString",
        "WordListType": "Regex",
        "WordList": [
            r"DBI\.connect\("
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # RelayRubyByExtension
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "RelayRubyByExtension",
        "MatchAction": "Relay",
        "RelayTargets": [
            "KeepRubyDbConnStrings",
            "KeepAwsKeysInCode",
            "KeepInlinePrivateKey",
            "KeepPassOrKeyInCode",
            "KeepSlackTokensInCode",
            "KeepSqlAccountCreation",
            "KeepDbConnStringPw"
        ],
        "Description": "Ruby scripts -> check DB connections, secrets",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [r"\.rb"],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # KeepNameContainsGreen
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepNameContainsGreen",
        "MatchAction": "Continue",
        "Description": "Flag filenames that contain certain keywords",
        "MatchLocation": "FileName",
        "WordListType": "Contains",
        "WordList": [
            r"passw",
            r"secret",
            r"credential",
            r"thycotic",
            r"cyberark"
        ],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # KeepShellRcFilesByName
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepShellRcFilesByName",
        "MatchAction": "Continue",
        "Description": "Interesting shell RC files by exact name",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [
            r"\.netrc",
            r"_netrc",
            r"\.exports",
            r"\.functions",
            r"\.extra",
            r"\.npmrc",
            r"\.env",
            r"\.bashrc",
            r"\.profile",
            r"\.zshrc"
        ],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # KeepGitCredsByName
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepGitCredsByName",
        "MatchAction": "Continue",
        "Description": "Git credentials file",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [
            r"\.git-credentials"
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # KeepShellHistoryByName
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepShellHistoryByName",
        "MatchAction": "Continue",
        "Description": "Shell history files by exact name",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [
            r"\.bash_history",
            r"\.zsh_history",
            r"\.sh_history",
            r"zhistory",
            r"\.irb_history",
            r"ConsoleHost_History\.txt"
        ],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # KeepCloudApiKeysByPath
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepCloudApiKeysByPath",
        "MatchAction": "Continue",
        "Description": "Path containing .aws\\ or doctl config => interesting",
        "MatchLocation": "FilePath",
        "WordListType": "Contains",
        "WordList": [
            r"\\\.aws\\",
            r"doctl\\config.yaml"
        ],
        "Triage": "Black",
    },

    # -------------------------------------------------------------------------
    # KeepCloudApiKeysByName
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepCloudApiKeysByName",
        "MatchAction": "Continue",
        "Description": "Files with .tugboat => interesting",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [
            r"\.tugboat"
        ],
        "Triage": "Black",
    },

    # -------------------------------------------------------------------------
    # RelayRdpByExtension => KeepRdpPasswords
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "RelayRdpByExtension",
        "MatchAction": "Relay",
        "RelayTargets": ["KeepRdpPasswords"],
        "Description": "Look inside .rdp files for password lines",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [
            r"\.rdp"
        ],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # KeepRdpPasswords
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "ContentsEnumeration",
        "RuleName": "KeepRdpPasswords",
        "MatchAction": "Continue",
        "Description": ".rdp with password lines",
        "MatchLocation": "FileContentAsString",
        "WordListType": "Regex",
        "WordList": [
            r"password 51\:b"
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # KeepRemoteAccessConfByExtension
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepRemoteAccessConfByExtension",
        "MatchAction": "Continue",
        "Description": "Various remote connection config files",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [
            r"\.rdg", r"\.rtsz", r"\.rtsx", r"\.ovpn", r"\.tvopt", r"\.sdtid"
        ],
        "Triage": "Yellow",
    },

    # -------------------------------------------------------------------------
    # KeepRemoteAccessConfByName
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepRemoteAccessConfByName",
        "MatchAction": "Continue",
        "Description": "Mobaxterm config files, other remote mgmt files",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [
            r"mobaxterm\.ini",
            r"mobaxterm backup\.zip",
            r"confCons.xml"
        ],
        "Triage": "Black",
    },

    # -------------------------------------------------------------------------
    # CertContentByEnding => Relay to KeepInlinePrivateKey
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "CertContentByEnding",
        "MatchAction": "Relay",
        "RelayTargets": ["KeepInlinePrivateKey"],
        "Description": "Files ending with _rsa, _dsa, etc => parse for private keys",
        "MatchLocation": "FileName",
        "WordListType": "EndsWith",
        "WordList": [
            r"_rsa",
            r"_dsa",
            r"_ed25519",
            r"_ecdsa"
        ],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # KeepSSHFilesByPath
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepSSHFilesByPath",
        "MatchAction": "Continue",
        "Description": "Anything in .ssh folder => very interesting",
        "MatchLocation": "FilePath",
        "WordListType": "Contains",
        "WordList": [
            r"\\\.ssh\\"
        ],
        "Triage": "Black",
    },

    # -------------------------------------------------------------------------
    # KeepSSHKeysByFileName
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepSSHKeysByFileName",
        "MatchAction": "Continue",
        "Description": "SSH private key by exact name (id_rsa, etc.)",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [
            r"id_rsa",
            r"id_dsa",
            r"id_ecdsa",
            r"id_ed25519"
        ],
        "Triage": "Black",
    },

    # -------------------------------------------------------------------------
    # KeepSSHKeysByFileExtension
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepSSHKeysByFileExtension",
        "MatchAction": "Continue",
        "Description": "PuTTY key files .ppk => interesting",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [
            r"\.ppk"
        ],
        "Triage": "Black",
    },

    # -------------------------------------------------------------------------
    # KeepFfLoginsJsonRelay => KeepFFRegexRed
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepFfLoginsJsonRelay",
        "MatchAction": "Relay",
        "RelayTargets": ["KeepFFRegexRed"],
        "Description": "Firefox logins.json => check for base64’d password fields",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [
            r"logins\.json"
        ],
        "Triage": "Green",
    },

    {
        "EnumerationScope": "ContentsEnumeration",
        "RuleName": "KeepFFRegexRed",
        "MatchAction": "Continue",
        "Description": "Firefox/Thunderbird logins => encryptedPassword field",
        "MatchLocation": "FileContentAsString",
        "WordListType": "Regex",
        "WordList": [
            r"\"encryptedPassword\":\"[A-Za-z0-9+/=]+\""
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # KeepPasswordFilesByName
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepPasswordFilesByName",
        "MatchAction": "Continue",
        "Description": "Common password file names",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [
            r"passwords\.txt",
            r"pass\.txt",
            r"accounts\.txt",
            r"passwords\.doc",
            r"pass\.doc",
            r"accounts\.doc",
            r"passwords\.xls",
            r"pass\.xls",
            r"accounts\.xls",
            r"passwords\.docx",
            r"pass\.docx",
            r"accounts\.docx",
            r"passwords\.xlsx",
            r"pass\.xlsx",
            r"accounts\.xlsx",
            r"secrets\.txt",
            r"secrets\.doc",
            r"secrets\.xls",
            r"secrets\.docx",
            r"BitlockerLAPSPasswords\.csv",
            r"secrets\.xlsx"
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # KeepPassMgrsByExtension
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepPassMgrsByExtension",
        "MatchAction": "Continue",
        "Description": "Known password-manager file extensions",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [
            r"\.kdbx",
            r"\.kdb",
            r"\.psafe3",
            r"\.kwallet",
            r"\.keychain",
            r"\.agilekeychain",
            r"\.cred"
        ],
        "Triage": "Black",
    },

    # -------------------------------------------------------------------------
    # KeepDbMgtConfigByName
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepDbMgtConfigByName",
        "MatchAction": "Continue",
        "Description": "Config for various DB management tools",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [
            r"SqlStudio\.bin",
            r"\.mysql_history",
            r"\.psql_history",
            r"\.pgpass",
            r"\.dbeaver-data-sources\.xml",
            r"credentials-config\.json",
            r"dbvis\.xml",
            r"robomongo\.json"
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # KeepWinHashesByName
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepWinHashesByName",
        "MatchAction": "Continue",
        "Description": "Windows local hash stores",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [
            r"NTDS\.DIT",
            r"SYSTEM",
            r"SAM",
            r"SECURITY"
        ],
        "Triage": "Black",
    },

    # -------------------------------------------------------------------------
    # KeepCyberArkConfigsByName
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepCyberArkConfigsByName",
        "MatchAction": "Continue",
        "Description": "CyberArk config/keys",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [
            r"Psmapp\.cred",
            r"psmgw\.cred",
            r"backup\.key",
            r"MasterReplicationUser\.pass",
            r"RecPrv\.key",
            r"ReplicationUser\.pass",
            r"Server\.key",
            r"VaultEmergency\.pass",
            r"VaultUser\.pass",
            r"Vault\.ini",
            r"PADR\.ini",
            r"PARAgent\.ini",
            r"CACPMScanner\.exe\.config",
            r"PVConfiguration\.xml"
        ],
        "Triage": "Black",
    },

    # -------------------------------------------------------------------------
    # KeepCyberArkByExtension
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepCyberArkByExtension",
        "MatchAction": "Continue",
        "Description": "CyberArk .cred / .pass files",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [
            r"\.cred",
            r"\.pass"
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # KeepDatabaseByExtension
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepDatabaseByExtension",
        "MatchAction": "Continue",
        "Description": "Database files (MSSQL, backups, etc.)",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [
            r"\.mdf",
            r"\.sdf",
            r"\.sqldump",
            r"\.bak"
        ],
        "Triage": "Yellow",
    },

    # -------------------------------------------------------------------------
    # RelayInfraConfigByExtension => KeepNetConfigCreds
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "RelayInfraConfigByExtension",
        "MatchAction": "Relay",
        "RelayTargets": ["KeepNetConfigCreds"],
        "Description": "Possible infrastructure config => check for network credentials",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [
            r"\.xml",
            r"\.json",
            r"\.config",
            r"\.ini",
            r"\.inf",
            r"\.cnf",
            r"\.conf",
            r"\.txt"
        ],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # KeepNetConfigCreds
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "ContentsEnumeration",
        "RuleName": "KeepNetConfigCreds",
        "MatchAction": "Continue",
        "Description": "Network device config lines with potential credentials",
        "MatchLocation": "FileContentAsString",
        "WordListType": "Regex",
        "WordList": [
            r"NVRAM config last updated",
            r"enable password \.",
            r"simple-bind authenticated encrypt",
            r"pac key [0-7] ",
            r"snmp-server community\s.+\sRW"
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # KeepNetConfigFileByName
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepNetConfigFileByName",
        "MatchAction": "Continue",
        "Description": "Cisco net configs by exact name",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [
            r"running-config\.cfg",
            r"startup-config\.cfg",
            r"running-config",
            r"startup-config"
        ],
        "Triage": "Black",
    },

    # -------------------------------------------------------------------------
    # RelayNetConfigByName => KeepNetConfigCreds
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "RelayNetConfigByName",
        "MatchAction": "Relay",
        "RelayTargets": ["KeepNetConfigCreds"],
        "Description": "Any file whose name contains cisco|router|firewall|switch => check for net config lines",
        "MatchLocation": "FileName",
        "WordListType": "Contains",
        "WordList": [
            r"cisco", r"router", r"firewall", r"switch"
        ],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # KeepFtpServerConfigByName
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepFtpServerConfigByName",
        "MatchAction": "Continue",
        "Description": "FTP server config or client config files",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [
            r"proftpdpasswd",
            r"filezilla\.xml"
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # KeepDefenderConfigByName
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepDefenderConfigByName",
        "MatchAction": "Continue",
        "Description": "Defender sensor config files",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [
            r"SensorConfiguration\.json",
            r"mdatp_managed\.json"
        ],
        "Triage": "Yellow",
    },

    # -------------------------------------------------------------------------
    # KeepDomainJoinCredsByName
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepDomainJoinCredsByName",
        "MatchAction": "Continue",
        "Description": "Customsettings.ini - used for domain join in deployment scenarios",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [
            r"customsettings\.ini"
        ],
        "Triage": "Yellow",
    },

    # -------------------------------------------------------------------------
    # KeepSCCMBootVarCredsByPath
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepSCCMBootVarCredsByPath",
        "MatchAction": "Continue",
        "Description": "SCCM Task Sequence variable files containing domain join or other secrets",
        "MatchLocation": "FilePath",
        "WordListType": "Regex",
        "WordList": [
            r"REMINST\\SMSTemp\\.*\.var",
            r"SMS\\data\\Variables\.dat",
            r"SMS\\data\\Policy\.xml"
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # KeepDeployImageByExtension
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepDeployImageByExtension",
        "MatchAction": "Continue",
        "Description": "Deployment images .wim, .ova, .ovf",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [
            r"\.wim",
            r"\.ova",
            r"\.ovf"
        ],
        "Triage": "Yellow",
    },

    # -------------------------------------------------------------------------
    # KeepDomainJoinCredsByPath
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepDomainJoinCredsByPath",
        "MatchAction": "Continue",
        "Description": "Paths containing control\\customsettings.ini => domain join creds",
        "MatchLocation": "FilePath",
        "WordListType": "Contains",
        "WordList": [
            r"control\\customsettings.ini"
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # RelayUnattendXml => KeepUnattendXmlRegexRed
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "RelayUnattendXml",
        "MatchAction": "Relay",
        "RelayTargets": ["KeepUnattendXmlRegexRed"],
        "Description": "unattend.xml => check embedded passwords",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [
            r"unattend\.xml",
            r"Autounattend\.xml"
        ],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # KeepUnattendXmlRegexRed
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "ContentsEnumeration",
        "RuleName": "KeepUnattendXmlRegexRed",
        "MatchAction": "Continue",
        "Description": "AdministratorPassword or AutoLogon credentials in unattend.xml",
        "MatchLocation": "FileContentAsString",
        "WordListType": "Regex",
        "WordList": [
            r"(?s)<AdministratorPassword>.{0,30}<Value>.*<\/Value>",
            r"(?s)<AutoLogon>.{0,30}<Value>.*<\/Value>"
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # DiscardByFileExtension
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "DiscardByFileExtension",
        "MatchAction": "Discard",
        "Description": "Skip non-text files (images, etc.)",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [
            r"\.bmp",
            r"\.eps",
            r"\.gif",
            r"\.ico",
            r"\.jfi",
            r"\.jfif",
            r"\.jif",
            r"\.jpe",
            r"\.jpeg",
            r"\.jpg",
            r"\.png",
            r"\.psd",
            r"\.svg",
            r"\.tif",
            r"\.tiff",
            r"\.webp",
            r"\.xcf",
            r"\.ttf",
            r"\.otf",
            r"\.lock",
            r"\.css",
            r"\.less",
            r"\.admx",
            r"\.adml",
            r"\.xsd",
            r"\.nse",
            r"\.xsl"
        ],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # DiscardByFileName
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "DiscardByFileName",
        "MatchAction": "Discard",
        "Description": "Skip specifically known safe templates",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [
            r"jmxremote\.password\.template",
            r"sceregvl\.inf"
        ],
        "Triage": "Green",
    },

    # -------------------------------------------------------------------------
    # KeepMemDumpByExtension
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepMemDumpByExtension",
        "MatchAction": "Continue",
        "Description": "Memory dumps .dmp",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [
            r"\.dmp"
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # KeepMemDumpByName
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepMemDumpByName",
        "MatchAction": "Continue",
        "Description": "lsass dumps, hiberfil.sys, memory.dmp",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [
            r"MEMORY\.DMP",
            r"hiberfil\.sys",
            r"lsass\.dmp",
            r"lsass\.exe\.dmp"
        ],
        "Triage": "Black",
    },

    # -------------------------------------------------------------------------
    # KeepInfraAsCodeByExtension
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepInfraAsCodeByExtension",
        "MatchAction": "Continue",
        "Description": "Infra as code -> cscfg, tfvars",
        "MatchLocation": "FileExtension",
        "WordListType": "Exact",
        "WordList": [
            r"\.cscfg",
            r"\.tfvars"
        ],
        "Triage": "Red",
    },

    # -------------------------------------------------------------------------
    # KeepJenkinsByName
    # -------------------------------------------------------------------------
    {
        "EnumerationScope": "FileEnumeration",
        "RuleName": "KeepJenkinsByName",
        "MatchAction": "Continue",
        "Description": "Jenkins credentials or configs",
        "MatchLocation": "FileName",
        "WordListType": "Exact",
        "WordList": [
            r"jenkins\.plugins\.publish_over_ssh\.BapSshPublisherPlugin\.xml",
            r"credentials\.xml"
        ],
        "Triage": "Red",
    },
]

###############################################################################
# 2. Build helper structures for quick rule lookups
###############################################################################

# Separate out the FileEnumeration vs ContentsEnumeration rules
file_enumeration_rules = []
contents_enumeration_rules = {}

for rule in RULES:
    scope = rule["EnumerationScope"]
    if scope == "FileEnumeration":
        file_enumeration_rules.append(rule)
    elif scope == "ContentsEnumeration":
        # Map rule by name for easy referencing
        contents_enumeration_rules[rule["RuleName"]] = rule
    # else skip unknown types

# Also map all rules by name for "Relay" references
all_rules_by_name = {}
for rule in RULES:
    all_rules_by_name[rule["RuleName"]] = rule

###############################################################################
# 3. Matching logic
###############################################################################


def file_matches_rule(file_path, file_name, file_extension, rule):
    """
    Returns True if the file matches the given FileEnumeration rule
    based on rule["MatchLocation"] and rule["WordListType"].
    """
    match_location = rule["MatchLocation"]
    wordlist_type = rule["WordListType"]
    wordlist = rule["WordList"]

    target_text = None
    if match_location == "FileExtension":
        target_text = file_extension
    elif match_location == "FileName":
        target_text = file_name
    elif match_location == "FilePath":
        # We'll use the entire path as normalized string
        target_text = file_path
    else:
        return False

    for pattern in wordlist:
        if wordlist_type == "Exact":
            # Pattern is a full-match for the string
            # But "exact" here typically means we want to see if the filename EXACTLY matches pattern
            # We'll interpret it as a python re match on the entire target_text
            # or do a simpler equality check ignoring regex meta
            if re.fullmatch(pattern, target_text, flags=re.IGNORECASE):
                return True

        elif wordlist_type == "Regex":
            if re.search(pattern, target_text, flags=re.IGNORECASE):
                return True

        elif wordlist_type == "Contains":
            if pattern.lower() in target_text.lower():
                return True

        elif wordlist_type == "EndsWith":
            if target_text.lower().endswith(pattern.lower()):
                return True

    return False


def file_content_matches_rule(file_path, rule):
    """
    Check if file content matches the given ContentsEnumeration rule.
    Return a list of matched lines or an empty list if no matches.
    We do a line-by-line regex search for demonstration; or a single pass.
    """
    matches = []
    regex_flags = re.IGNORECASE | re.DOTALL if "Regex" == rule["WordListType"] else re.IGNORECASE

    try:
        with open(file_path, mode="r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        for pattern in rule["WordList"]:
            # We'll do a global search
            for m in re.finditer(pattern, content, flags=regex_flags):
                snippet = m.group(0)
                # For extremely large matches, truncate
                snippet = (snippet[:75] + '...') if len(snippet) > 75 else snippet
                matches.append(f"match => {snippet}")
    except Exception as e:
        # Possibly a binary file or read error
        return []

    return matches


###############################################################################
# 4. Main scanning logic
###############################################################################

def scan_file(filepath):
    """
    Check a single file against all FileEnumeration rules. Possibly do content checks
    if the rule says Relay => we run the corresponding contents rules.
    Returns a list of lines describing any hits.
    """
    results = []
    file_name = os.path.basename(filepath)
    # extension: simplest approach => everything after last dot; or empty if none
    # (In the rules, we see ".py", ".ini", etc.)
    _, dot, ext = file_name.rpartition(".")
    file_extension = f".{ext}" if dot else ""

    # Evaluate all file-enumeration rules in order:
    for rule in file_enumeration_rules:
        if file_matches_rule(filepath, file_name, file_extension, rule):
            action = rule["MatchAction"]
            rule_name = rule["RuleName"]
            triage = rule.get("Triage", "Unknown")

            if action == "Discard":
                # Skip any further rules or content checks
                # Return empty result right away
                return []

            elif action == "Continue":
                # We log the match
                desc = rule.get("Description", "")
                results.append(f"[{rule_name}][{triage}] {filepath} => {desc}")
                # but continue checking other rules (some tools do short-circuit; here we do not forcibly stop)
                # depends on your desired logic

            elif action == "Relay":
                # We look up the "RelayTargets" => those are content rules to run
                for target_rule_name in rule.get("RelayTargets", []):
                    target_rule = contents_enumeration_rules.get(target_rule_name)
                    if target_rule:
                        # Perform content search
                        content_matches = file_content_matches_rule(filepath, target_rule)
                        if content_matches:
                            triage2 = target_rule.get("Triage", "Unknown")
                            desc2 = target_rule.get("Description", "")
                            for match_line in content_matches:
                                results.append(
                                    f"[{target_rule_name}][{triage2}] {filepath} => {desc2} | {match_line}"
                                )

            elif action == "CheckForKeys":
                # Example if you want a special action for x509 or PKCS12
                # This script simply does a content-based check as well
                # or you might parse the certificate
                # We'll just reuse the "KeepInlinePrivateKey" rule for demonstration:
                content_rule = contents_enumeration_rules.get("KeepInlinePrivateKey")
                if content_rule:
                    content_matches = file_content_matches_rule(filepath, content_rule)
                    if content_matches:
                        triage2 = content_rule.get("Triage", "Unknown")
                        desc2 = content_rule.get("Description", "")
                        for match_line in content_matches:
                            results.append(
                                f"[{content_rule['RuleName']}][{triage2}] {filepath} => {desc2} | {match_line}"
                            )

            # else: no default

    return results


def scan_share(share_path):
    """
    Recursively walk the share_path directory, scanning each file with the above logic.
    Print out findings to stdout.
    """
    for root, dirs, files in os.walk(share_path):
        for fname in files:
            full_path = os.path.join(root, fname)
            hits = scan_file(full_path)
            for line in hits:
                with open(output_file, "w", encoding="utf-8") as out_f:
                    out_f.write(line + "\n")
                print(line)


###############################################################################
# 5. Main entry point
###############################################################################

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <share_path_to_scan> <outputfile>")
        sys.exit(1)

    share_path = sys.argv[1]
    output_file = sys.argv[2]
    if not os.path.isdir(share_path):
        print(f"Error: {share_path} is not a directory.")
        sys.exit(1)

    scan_share(share_path, output_file)

if __name__ == "__main__":
    main()
