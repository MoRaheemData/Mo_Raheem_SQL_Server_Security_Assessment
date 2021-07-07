/****************************************************************************************************************

Mo Raheem's SQL Server Security Assessment 
	
	~ One script to rule them all, one script to find them, ~
	~ One script to bring them all, and in the darkness bind them; ~
	~ In the Land of SQL Server where the shadows lie. ~

Compitable with and tested on - SQL Server 2017

License: https://github.com/MoRaheemData/Mo_Raheem_SQL_Server_Security_Assessment/blob/main/LICENSE

GitHub: https://github.com/MoRaheemData/Mo_Raheem_SQL_Server_Security_Assessment

Version: 2021-07-07 12:30

You can contact me by e-mail at MoRaheemData@gmail.com.

M.A. Raheem
Website ()

HOW TO USE: 
	- User running must be [securityadmin] or higher.
	- Set parameters in the "Parameters to be set by user" section.
	- Run on the instance in question.
	- Copy the dynamically created query from the 'Results' pane (sans "Completion time..." message) and run in a new query window.

NOTES: 
	- Messages pane will display dynamically created query which you will need to run in a new Query Window.
	- An additional check for uncommon securables is run at the end - it usually shows up as blank.
		- Submit a feature request if you want a class added to the script.
	- If you use AD Groups a membership check is performed so the user's true permissions are reported.
		- This is done by using the extended stored procedure xp_logininfo.
		- If an AD Group is a member of another AD Group, than that sub-group is also checked, and so on.
		- A drawback of xp_logininfo is that the AD Group must exist on the instance, if it isn't then the script 
			will create the principal, check its membership, and then drop it.
	- Permissions of built-in SQL Server roles are not checked (eg. sysadmin, db_datareader, etc.).
	- What information is returned?
		- Instance-level permissions and roles of the prinicpal and its AD Groups.
		- Database roles of the prinicpal and its AD Groups.
		- Database-level permissions for the database roles of the prinicpal and its AD Groups.
		- Database-level permissions of the prinicpal and its AD Groups.
		- Permissions to securables that the author considers uncommon of the prinicpal and its AD Groups.

****************************************************************************************************************/

USE [master]; 
GO

SET NOCOUNT ON;

/* Parameters to be set by user */
DECLARE @PrincipalOrRole [nvarchar](128) = 'MyDomain\moraheem' /* Specify the principal or role in question (eg. MyDomain\moraheem), or leave NULL and set @PrintPublicRolePerms = 1 to just print [public]'s permissions. */
DECLARE @PrintPublicRolePerms [bit] = 0 /* Specify whether [public] role permissions should be printed. 1 = Yes & 0 = No. */
DECLARE @DatabaseScope [nvarchar](max) = 'ALL' /* Specify whether scope should be ALL, NONE, a specific database, or comma separated list of database names. */
/* Other needed variables */
DECLARE @Public [nvarchar](6);
DECLARE @Count [int];
DECLARE @DatabaseName [nvarchar](128);
DECLARE @CreateTable [nvarchar](1000);
DECLARE @InsertTable [nvarchar](max);
DECLARE @ADGroupString [nvarchar](max);
DECLARE @ErrorMessage AS [nvarchar](1000);


/***********************
	Parameter checks	
***********************/
/* Make sure parameters are valid, else raise error */
IF @PrincipalOrRole IS NULL AND @PrintPublicRolePerms = 0
BEGIN
	SET @ErrorMessage = N'Specify @PrincipalOrRole as a principal or role, or set @PrintPublicRolePerms to 1.';
	RAISERROR('%s', 16, 1, @ErrorMessage) WITH NOWAIT;
END

IF LEN(@PrincipalOrRole) < 1
BEGIN
	SET @ErrorMessage = N'Specify valid @PrincipalOrRole.';
	RAISERROR('%s', 16, 1, @ErrorMessage) WITH NOWAIT;
END

IF @DatabaseScope IS NULL 
BEGIN 
	SET @ErrorMessage = N'Specify @DatabaseScope - cannot be NULL. Choose either ALL, NONE, or a valid database.';
	RAISERROR('%s', 16, 1, @ErrorMessage) WITH NOWAIT;
END

IF @DatabaseScope IS NOT NULL
BEGIN
	IF @DatabaseScope != 'ALL' AND @DatabaseScope != 'NONE'
	BEGIN
		DROP TABLE IF EXISTS #DatabaseCheck;
		CREATE TABLE #DatabaseCheck (
			[DatabaseName] [nvarchar](128)
		);

		INSERT INTO #DatabaseCheck ( [DatabaseName] )
		SELECT [value] FROM STRING_SPLIT(@DatabaseScope, ',');

		SELECT 
			@Count = COUNT([DatabaseName])
		FROM 
			#DatabaseCheck
		WHERE 
			[DatabaseName] NOT IN ( SELECT [name] FROM [master].[sys].[databases] WHERE [state_desc] = 'ONLINE' AND [user_access_desc] = 'MULTI_USER' );

		IF @Count > 0
		BEGIN 
			SET @ErrorMessage = N'Specify valid databases. A database in the @DatabaseScope parameter is not a valid database, or is not available.';
			RAISERROR('%s', 16, 1, @ErrorMessage) WITH NOWAIT;
		END
	END
END

/* Set @Public */
IF @PrintPublicRolePerms = 1
BEGIN
	SET @Public = 'public';
END 
IF @PrintPublicRolePerms = 0
BEGIN
	SET @Public = 'R6fxQy';
END 

/* Set @PrincipalOrRole */
IF @PrincipalOrRole IS NULL
BEGIN
	SET @PrincipalOrRole = 'R6fxQy';
END

/***********************************
	Gather AD Group membership		
***********************************/

/* Gather all Windows Users & Groups from syslogins */
DROP TABLE IF EXISTS #SysLogins;
CREATE TABLE #SysLogins (
	[name] [nvarchar](128) NOT NULL,
	[status] [varchar](8) NULL,
	[isntgroup] [int] NULL,
	[MemberOfGroup] [nvarchar](256) NULL
);

INSERT INTO #SysLogins ( [name],[status],[isntgroup] )
SELECT 
	[name],
	CASE [status]
		WHEN 9 THEN 'Enabled'
		WHEN 10 THEN 'Disabled'
		ELSE '???' 
	END AS 'Status',
	[isntgroup] /* 1 = Login is a Windows group */
FROM 
	[master].[sys].[syslogins]
WHERE 
	[isntgroup] = 1;

/* Gather all members of Windows Groups */
DROP TABLE IF EXISTS #NtGroup;
CREATE TABLE #NtGroup (
	[name] [nvarchar](128) NOT NULL,
	[IsProcessed] [BIT] DEFAULT 0 
);

DROP TABLE IF EXISTS #ADGroupMember; 
CREATE TABLE #ADGroupMember ( 
	[account name] [nvarchar](128),
	[type] [nvarchar](128),
	[privilege] [nvarchar](128),
	[mapped login name] [nvarchar](128),
	[permission path] [nvarchar](128)
);

INSERT INTO #NtGroup ( [name] )
SELECT 
	[name]
FROM 
	#SysLogins;

WHILE EXISTS ( SELECT TOP 1 [name] FROM #NtGroup WHERE [IsProcessed] = 0 )
BEGIN
	DECLARE @NtName [nvarchar](128);

	SELECT TOP 1 
		@NtName = [name]
	FROM 
		#NtGroup 
	WHERE 
		[IsProcessed] = 0;
	
	INSERT INTO #ADGroupMember ( [account name], [type], [privilege], [mapped login name], [permission path] )
	EXEC [master]..[xp_logininfo] @acctname = @NtName, @option = 'members';

	UPDATE #NtGroup
	SET 
		[IsProcessed] = 1
	WHERE
		[name] = @NtName;
END

INSERT INTO #SysLogins ( [name],[status],[isntgroup],[MemberOfGroup] )
SELECT 
	a.[account name],
	s.[status],
	s.[isntgroup],
	a.[permission path]
FROM
	#ADGroupMember a
	LEFT OUTER JOIN #SysLogins s 
		ON s.[name] = a.[permission path];

DROP TABLE IF EXISTS #GroupLoop;
CREATE TABLE #GroupLoop (
	[account name] [nvarchar](128),
	[type] [nvarchar](128),
	[privilege] [nvarchar](128),
	[mapped login name] [nvarchar](128),
	[permission path] [nvarchar](max),
	[IsProcessed] [BIT] DEFAULT 0
);

INSERT INTO #GroupLoop ( [account name],[type],[privilege],[mapped login name],[permission path] )
SELECT 
	[account name],
	[type],
	[privilege],
	[mapped login name],
	[permission path]
FROM 
	#ADGroupMember
WHERE 
	[type] = 'group';

/* Clear table to repopulate for Group Loop */
TRUNCATE TABLE #ADGroupMember;

WHILE EXISTS ( SELECT TOP 1 [account name] FROM #GroupLoop WHERE [IsProcessed] = 0 AND [type] = 'group' )
BEGIN
	DECLARE @GroupName [nvarchar](128);
	DECLARE @CreateGroup [tinyint] = 0;
	DECLARE @SQLStmt [nvarchar](1000);

	SELECT TOP 1 
		@GroupName = [account name]
	FROM 
		#GroupLoop 
	WHERE 
		[IsProcessed] = 0
		AND [type] = 'group';

	/* xp_logininfo won't return info if group does not explicitly exist. So if it doesn't then a CREATE/DROP is performed. */
	SELECT 
		@CreateGroup = COUNT([name]) 
	FROM 
		[master].[sys].[syslogins] 
	WHERE 
		[name] = @GroupName;

	IF @CreateGroup = 0
	BEGIN 
		SET @SQLStmt = 'CREATE LOGIN [' + @GroupName + '] FROM WINDOWS WITH DEFAULT_DATABASE=[master];';
		EXEC(@SQLStmt);
		
		INSERT INTO #ADGroupMember ( [account name], [type], [privilege], [mapped login name], [permission path] )
		EXEC [master]..[xp_logininfo] @acctname = @GroupName, @option = 'members';

		SET @SQLStmt = 'DROP LOGIN [' + @GroupName + '];';
		EXEC(@SQLStmt);
	END
	
	IF @CreateGroup > 0
	BEGIN 
		INSERT INTO #ADGroupMember ( [account name], [type], [privilege], [mapped login name], [permission path] )
		EXEC [master]..[xp_logininfo] @acctname = @GroupName, @option = 'members';
	END

	INSERT INTO #SysLogins ( [name],[status],[isntgroup],[MemberOfGroup] )
	SELECT 
		a.[account name],
		s.[status],
		s.[isntgroup],
		g.[permission path] 
	FROM
		#ADGroupMember a
		LEFT OUTER JOIN #SysLogins s 
			ON s.[name] = a.[permission path]
		LEFT OUTER JOIN #GroupLoop g
			ON g.[account name] = a.[permission path]
	WHERE 
		s.[MemberOfGroup] IS NOT NULL;

	/* If a member is a group than this group is added to #GroupLoop to be checked also */
	INSERT INTO #GroupLoop ( [account name],[type],[privilege],[mapped login name],[permission path] )
	SELECT 
		[account name],
		[type],
		[privilege],
		[mapped login name],
		[permission path]
	FROM 
		#ADGroupMember
	WHERE 
		[type] = 'group';

	TRUNCATE TABLE #ADGroupMember;

	UPDATE #GroupLoop
	SET 
		[IsProcessed] = 1
	WHERE 
		[account name] = @GroupName;
END

DROP TABLE IF EXISTS #PrincipalsADGroups;
CREATE TABLE #PrincipalsADGroups (
	[ADGroup] [nvarchar](256)
);

INSERT #PrincipalsADGroups ( [ADGroup] )
SELECT DISTINCT
	[MemberOfGroup]
FROM 
	#SysLogins
WHERE 
	[name] IN ( @PrincipalOrRole )
	AND [name] IS NOT NULL;

IF ( SELECT COUNT([ADGroup]) FROM #PrincipalsADGroups WHERE [ADGroup] IS NOT NULL ) > 0
BEGIN
	SELECT 
		@Count = COUNT([ADGroup]) 
	FROM 
		#PrincipalsADGroups
	WHERE 
		[ADGroup] IS NOT NULL;
	
	INSERT #PrincipalsADGroups ( [ADGroup] )
	SELECT 
		[MemberOfGroup]
	FROM 
		#SysLogins
	WHERE
		[name] IN ( SELECT [ADGroup] FROM #PrincipalsADGroups WHERE [ADGroup] IS NOT NULL)
		AND [MemberOfGroup] NOT IN ( SELECT [ADGroup] FROM #PrincipalsADGroups WHERE [ADGroup] IS NOT NULL);

	WHILE @@ROWCOUNT > @Count
	BEGIN
		INSERT #PrincipalsADGroups ( [ADGroup] )
		SELECT 
			[MemberOfGroup]
		FROM 
			#SysLogins
		WHERE
			[name] IN ( SELECT [ADGroup] FROM #PrincipalsADGroups WHERE [ADGroup] IS NOT NULL)
			AND [MemberOfGroup] NOT IN ( SELECT [ADGroup] FROM #PrincipalsADGroups WHERE [ADGroup] IS NOT NULL);

		SELECT 
			@Count = COUNT([ADGroup]) 
		FROM 
			#PrincipalsADGroups
		WHERE 
			[ADGroup] IS NOT NULL;
	END
END

/* Create string of principals AG Groups */
SELECT 
	@ADGroupString =  COALESCE(@ADGroupString + ''',''', '') + [ADGroup] 
FROM 
	#PrincipalsADGroups
WHERE 
	[ADGroup] IS NOT NULL;

IF LEN(@ADGroupString) < 1 OR @ADGroupString IS NULL
BEGIN
	SET @ADGroupString = 'R6fxQy';
END

/***************************************
	Gather instance-level permissions	
***************************************/
DECLARE @InstanceStmt [nvarchar](max);
SET @InstanceStmt = '
SELECT 
	@@SERVERNAME AS [ServerName], 
	''Instance-Level'' AS [Scope], 
	prin.[name] AS [PrincipalName],
	prin.[type_desc] AS [PrincipalType],
	CASE prin.[is_disabled]
		WHEN 0 THEN ''No''
		WHEN 1 THEN ''Yes''
		ELSE ''???''
	END AS [IsDisabled], 
	perm.[permission_name] AS [PermissionType], 
	perm.[state_desc] AS [PermissionState], 
	perm.[class_desc] AS [ClassDescription], 
	COALESCE(e.[name], prin1.[name], ''N/A'') AS [EndpointName],
	GETDATE() AS [PollDate]
FROM 
	[sys].[server_principals] AS prin
	JOIN [sys].[server_permissions] AS perm 
		ON perm.[grantee_principal_id] = prin.[principal_id]
	LEFT JOIN [sys].[endpoints] AS e
		ON e.[endpoint_id] = perm.[major_id]
	LEFT OUTER JOIN [master].[sys].[server_principals] prin1
		ON prin1.[principal_id] = perm.[major_id]
WHERE 
	prin.[name] IN ('; 

SET @InstanceStmt += '''' + @Public + '''';

IF @PrincipalOrRole IS NOT NULL
BEGIN
	SET @InstanceStmt += ',''' + @PrincipalOrRole + '''';
END
IF @ADGroupString IS NOT NULL
BEGIN
	SET @InstanceStmt += ',''' + @ADGroupString + ''')';
END 
ELSE
	SET @InstanceStmt += ')';

SET @InstanceStmt += '
UNION ALL
SELECT 
	@@SERVERNAME AS [ServerName], 
	''Instance-Level'' AS [Scope],
	[name] AS [PrincipalName],
	CASE 
		WHEN [isntgroup] = 1 THEN ''WINDOWS_GROUP''
		WHEN [isntuser] = 1 THEN ''WINDOWS_LOGIN''
		WHEN [isntname] = 0 THEN ''SQL_LOGIN''
	END AS [PermissionType], 
	CASE [status]
		WHEN 9 THEN ''No''
		ELSE ''Yes''
	END AS [IsDisabled], 
	''Database Role'' AS [PermissionType], 
	''GRANT'' AS [PermissionState], 
	''SERVER'' AS [ClassDescription],
	''sysadmin'' AS [EndpointName],
	GETDATE() AS [PollDate]
FROM 
	[master].[sys].[syslogins]
WHERE
	[name] IN (''' + @PrincipalOrRole + '' + ''',''' + @ADGroupString + ''',''' + @Public + ''')
	AND [sysadmin] = 1';
PRINT @InstanceStmt;
SET @InstanceStmt = '
UNION ALL
SELECT 
	@@SERVERNAME AS [ServerName], 
	''Instance-Level'' AS [Scope],
	[name] AS [PrincipalName],
	CASE 
		WHEN [isntgroup] = 1 THEN ''WINDOWS_GROUP''
		WHEN [isntuser] = 1 THEN ''WINDOWS_LOGIN''
		WHEN [isntname] = 0 THEN ''SQL_LOGIN''
	END AS [PermissionType], 
	CASE [status]
		WHEN 9 THEN ''No''
		ELSE ''Yes''
	END AS [IsDisabled], 
	''Database Role'' AS [PermissionType], 
	''GRANT'' AS [PermissionState], 
	''SERVER'' AS [ClassDescription],
	''securityadmin'' AS [EndpointName],
	GETDATE() AS [PollDate]
FROM 
	[master].[sys].[syslogins]
WHERE
	[name] IN (''' + @PrincipalOrRole + '' + ''',''' + @ADGroupString + ''',''' + @Public + ''')
	AND [securityadmin] = 1';
PRINT @InstanceStmt;
SET @InstanceStmt = '
UNION ALL
SELECT 
	@@SERVERNAME AS [ServerName], 
	''Instance-Level'' AS [Scope],
	[name] AS [PrincipalName],
	CASE 
		WHEN [isntgroup] = 1 THEN ''WINDOWS_GROUP''
		WHEN [isntuser] = 1 THEN ''WINDOWS_LOGIN''
		WHEN [isntname] = 0 THEN ''SQL_LOGIN''
	END AS [PermissionType], 
	CASE [status]
		WHEN 9 THEN ''No''
		ELSE ''Yes''
	END AS [IsDisabled], 
	''Database Role'' AS [PermissionType], 
	''GRANT'' AS [PermissionState], 
	''SERVER'' AS [ClassDescription],
	''serveradmin'' AS [EndpointName],
	GETDATE() AS [PollDate]
FROM 
	[master].[sys].[syslogins]
WHERE
	[name] IN (''' + @PrincipalOrRole + '' + ''',''' + @ADGroupString + ''',''' + @Public + ''')
	AND [serveradmin] = 1';
PRINT @InstanceStmt;
SET @InstanceStmt = '
UNION ALL
SELECT 
	@@SERVERNAME AS [ServerName], 
	''Instance-Level'' AS [Scope],
	[name] AS [PrincipalName],
	CASE 
		WHEN [isntgroup] = 1 THEN ''WINDOWS_GROUP''
		WHEN [isntuser] = 1 THEN ''WINDOWS_LOGIN''
		WHEN [isntname] = 0 THEN ''SQL_LOGIN''
	END AS [PermissionType], 
	CASE [status]
		WHEN 9 THEN ''No''
		ELSE ''Yes''
	END AS [IsDisabled], 
	''Database Role'' AS [PermissionType], 
	''GRANT'' AS [PermissionState], 
	''SERVER'' AS [ClassDescription],
	''setupadmin'' AS [EndpointName],
	GETDATE() AS [PollDate]
FROM 
	[master].[sys].[syslogins]
WHERE
	[name] IN (''' + @PrincipalOrRole + '' + ''',''' + @ADGroupString + ''',''' + @Public + ''')
	AND [setupadmin] = 1';
PRINT @InstanceStmt;
SET @InstanceStmt = '
UNION ALL
SELECT 
	@@SERVERNAME AS [ServerName], 
	''Instance-Level'' AS [Scope],
	[name] AS [PrincipalName],
	CASE 
		WHEN [isntgroup] = 1 THEN ''WINDOWS_GROUP''
		WHEN [isntuser] = 1 THEN ''WINDOWS_LOGIN''
		WHEN [isntname] = 0 THEN ''SQL_LOGIN''
	END AS [PermissionType], 
	CASE [status]
		WHEN 9 THEN ''No''
		ELSE ''Yes''
	END AS [IsDisabled], 
	''Database Role'' AS [PermissionType], 
	''GRANT'' AS [PermissionState], 
	''SERVER'' AS [ClassDescription],
	''processadmin'' AS [EndpointName],
	GETDATE() AS [PollDate]
FROM 
	[master].[sys].[syslogins]
WHERE
	[name] IN (''' + @PrincipalOrRole + '' + ''',''' + @ADGroupString + ''',''' + @Public + ''')
	AND [processadmin] = 1';
PRINT @InstanceStmt;
SET @InstanceStmt = '
UNION ALL
SELECT 
	@@SERVERNAME AS [ServerName], 
	''Instance-Level'' AS [Scope],
	[name] AS [PrincipalName],
	CASE 
		WHEN [isntgroup] = 1 THEN ''WINDOWS_GROUP''
		WHEN [isntuser] = 1 THEN ''WINDOWS_LOGIN''
		WHEN [isntname] = 0 THEN ''SQL_LOGIN''
	END AS [PermissionType], 
	CASE [status]
		WHEN 9 THEN ''No''
		ELSE ''Yes''
	END AS [IsDisabled], 
	''Database Role'' AS [PermissionType], 
	''GRANT'' AS [PermissionState], 
	''SERVER'' AS [ClassDescription],
	''diskadmin'' AS [EndpointName],
	GETDATE() AS [PollDate]
FROM 
	[master].[sys].[syslogins]
WHERE
	[name] IN (''' + @PrincipalOrRole + '' + ''',''' + @ADGroupString + ''',''' + @Public + ''')
	AND [diskadmin] = 1';
PRINT @InstanceStmt;
SET @InstanceStmt = '
UNION ALL
SELECT 
	@@SERVERNAME AS [ServerName], 
	''Instance-Level'' AS [Scope],
	[name] AS [PrincipalName],
	CASE 
		WHEN [isntgroup] = 1 THEN ''WINDOWS_GROUP''
		WHEN [isntuser] = 1 THEN ''WINDOWS_LOGIN''
		WHEN [isntname] = 0 THEN ''SQL_LOGIN''
	END AS [PermissionType], 
	CASE [status]
		WHEN 9 THEN ''No''
		ELSE ''Yes''
	END AS [IsDisabled], 
	''Database Role'' AS [PermissionType], 
	''GRANT'' AS [PermissionState], 
	''SERVER'' AS [ClassDescription],
	''dbcreator'' AS [EndpointName],
	GETDATE() AS [PollDate]
FROM 
	[master].[sys].[syslogins]
WHERE
	[name] IN (''' + @PrincipalOrRole + '' + ''',''' + @ADGroupString + ''',''' + @Public + ''')
	AND [dbcreator] = 1';
PRINT @InstanceStmt;
SET @InstanceStmt = '
UNION ALL
SELECT 
	@@SERVERNAME AS [ServerName], 
	''Instance-Level'' AS [Scope],
	[name] AS [PrincipalName],
	CASE 
		WHEN [isntgroup] = 1 THEN ''WINDOWS_GROUP''
		WHEN [isntuser] = 1 THEN ''WINDOWS_LOGIN''
		WHEN [isntname] = 0 THEN ''SQL_LOGIN''
	END AS [PermissionType], 
	CASE [status]
		WHEN 9 THEN ''No''
		ELSE ''Yes''
	END AS [IsDisabled], 
	''Database Role'' AS [PermissionType], 
	''GRANT'' AS [PermissionState], 
	''SERVER'' AS [ClassDescription],
	''bulkadmin'' AS [EndpointName],
	GETDATE() AS [PollDate]
FROM 
	[master].[sys].[syslogins]
WHERE
	[name] IN (''' + @PrincipalOrRole + '' + ''',''' + @ADGroupString + ''',''' + @Public + ''')
	AND [bulkadmin] = 1';
PRINT @InstanceStmt;


/***************************************************
	Gather permissions in and for each database		
***************************************************/
DROP TABLE IF EXISTS #DatabaseName;
CREATE TABLE #DatabaseName (
	[DatabaseName] [nvarchar](128) NOT NULL,
	[IsProcessed] [BIT] DEFAULT 0
);

IF @DatabaseScope = 'ALL'
BEGIN
	INSERT INTO #DatabaseName ( [DatabaseName] )
	SELECT 
		[name]
	FROM 
		[master].[sys].[databases]
	WHERE 
		[state_desc] = 'ONLINE'
		AND [user_access_desc] = 'MULTI_USER'
	ORDER BY 
		[name] ASC;
END
IF @DatabaseScope != 'ALL' AND @DatabaseScope IS NOT NULL
BEGIN
	INSERT INTO #DatabaseName ( [DatabaseName] )
	SELECT [value] FROM STRING_SPLIT(@DatabaseScope, ',');
END

IF @DatabaseScope != 'NONE' AND @DatabaseScope IS NOT NULL
BEGIN

/* Gather database role membership */
DROP TABLE IF EXISTS ##Role_7FF7C4A15E074DC899DC11BD248EB6C6;
CREATE TABLE ##Role_7FF7C4A15E074DC899DC11BD248EB6C6 (
	[DatabaseName] [nvarchar](128) NOT NULL,
	[RoleName] [nvarchar](128) NOT NULL,
	[IsProcessed] [bit] DEFAULT 0 NOT NULL 
);

WHILE EXISTS ( SELECT TOP 1 [DatabaseName] FROM #DatabaseName WHERE [IsProcessed] = 0 )
BEGIN
	DECLARE @RoleStmt [nvarchar](max);
	
	SELECT TOP 1
		@DatabaseName = [DatabaseName]
	FROM 
		#DatabaseName 
	WHERE 
		[IsProcessed] = 0
	ORDER BY 
		[DatabaseName] ASC;

	SET @RoleStmt = '
	SELECT
		@@SERVERNAME AS [ServerName], 
		''' + @DatabaseName + ''' AS [Scope],
		prin.[name] AS [PrinicpalName],
		prin.[type_desc] AS [PrincipalType],
		prin1.[name] AS [DatabaseRole],
		GETDATE() AS [PollDate]
	FROM [' + @DatabaseName + '].[sys].[database_principals] prin
		INNER JOIN [' + @DatabaseName + '].[sys].[database_role_members] mem
			ON mem.[member_principal_id] = prin.[principal_id]
		INNER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin1
			ON prin1.[principal_id] = mem.[role_principal_id]
	WHERE 
		prin.[name] IN (''' + @Public + ''',''' + @PrincipalOrRole + '' + ''',''' + @ADGroupString + ''')
	UNION ALL';
	PRINT @RoleStmt;
	
	SET @InsertTable = '
	INSERT INTO ##Role_7FF7C4A15E074DC899DC11BD248EB6C6 ( [DatabaseName], [RoleName] )
	SELECT
		''' + @DatabaseName + ''' AS [Scope],
		prin1.[name] AS [DatabaseRole]
	FROM [' + @DatabaseName + '].[sys].[database_principals] prin
		INNER JOIN [' + @DatabaseName + '].[sys].[database_role_members] mem
			ON mem.[member_principal_id] = prin.[principal_id]
		INNER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin1
			ON prin1.[principal_id] = mem.[role_principal_id]
	WHERE 
		prin.[name] IN (''' + @Public + ''',''' + @PrincipalOrRole + '' + ''',''' + @ADGroupString + ''')
		AND prin1.[name] NOT IN (''db_accessadmin'',''db_backupoperator'',''db_datareader'',''db_datawriter'',''db_ddladmin'',''db_denydatareader'',''db_denydatawriter'',''db_owner'',''db_securityadmin'',''DatabaseMailUserRole'',''db_ssisadmin'',''db_ssisltduser'',''db_ssisoperator'',''dc_admin'',''dc_operator'',''dc_proxy'',''PolicyAdministratorRole'',''ServerGroupAdministratorRole'',''ServerGroupReaderRole'',''SQLAgentOperatorRole'',''SQLAgentReaderRole'',''SQLAgentUserRole'',''TargetServersRole'',''UtiltyCMRReader'',''UtiltyIMRReader'',''UtiltyIMRWriter'');
	/* Exclude SQL Server built-in roles */';
	EXEC(@InsertTable);

	UPDATE #DatabaseName
	SET 
		[IsProcessed] = 1
	WHERE 
		[DatabaseName] = @DatabaseName;
END

/* Cleave off last UNION ALL */
SET @RoleStmt = SUBSTRING(@RoleStmt, 0, (LEN(@RoleStmt)-9));
PRINT @RoleStmt;

/* Reset database name temp table */
UPDATE #DatabaseName
SET [IsProcessed] = 0;

/* Gather database object permissions for roles */
WHILE EXISTS ( SELECT TOP 1 [DatabaseName] FROM #DatabaseName WHERE [IsProcessed] = 0 )
BEGIN
	DECLARE @UserRoleStmt [nvarchar](max);
	DECLARE @RoleString [nvarchar](max);

	SELECT TOP 1
		@DatabaseName = [DatabaseName]
	FROM 
		#DatabaseName 
	WHERE 
		[IsProcessed] = 0
	ORDER BY 
		[DatabaseName] ASC;
	
	SELECT 
		@RoleString =  COALESCE(@RoleString + ''',''', '') + [RoleName] 
	FROM 
		##Role_7FF7C4A15E074DC899DC11BD248EB6C6 
	WHERE 
		[DatabaseName] = @DatabaseName ;
	
	SET @UserRoleStmt = '
	/* [class] = 0 = Database */
	SELECT
		@@SERVERNAME AS [ServerName],
		''' + @DatabaseName + ''' AS [Scope],
		prin.[name] AS [PrincipalName],
		perm.[class_desc] AS [ObjectType],
		perm.[permission_name] AS [PermissionType],
		perm.[state_desc] AS [PermissionState],
		''N/A'' AS [SchemaName],
		''N/A'' AS [ObjectName],
		''N/A'' AS [ColumnName],
		GETDATE() AS [PollDate]
	FROM
		[' + @DatabaseName + '].[sys].[database_permissions] perm
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin 
		ON prin.[principal_id] = perm.[grantee_principal_id]
	WHERE
		perm.[grantee_principal_id] IN ( SELECT [principal_id] FROM [' + @DatabaseName + '].[sys].[database_principals] WHERE [name] IN (''' + @RoleString + ''') ) 
		AND perm.[class] = 0 /* 0 = DATABASE */ 
	UNION ALL';
	PRINT @UserRoleStmt;
	SET @UserRoleStmt = '
	/* [class] = 1 = Object or Column */
	SELECT
		@@SERVERNAME AS [ServerName],
		''' + @DatabaseName + '''  AS [Scope],
		prin.[name] AS [PrincipalName],
		ISNULL(obj.[type_desc], perm.[class_desc]) AS [ObjectType],
		perm.[permission_name] AS [PermissionType],
		perm.[state_desc] AS [PermissionState],
		ISNULL(s.[name], ''Unknown'') AS [SchemaName],
		COALESCE(obj.[name], OBJECT_NAME(perm.[major_id]), ''N/A'') AS [ObjectName],
		ISNULL(c.[name], ''N/A'') AS [ColumnName],
		GETDATE() AS [PollDate]
	FROM
		[' + @DatabaseName + '].[sys].[database_permissions] perm
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin 
		ON prin.[principal_id] = perm.[grantee_principal_id]
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[all_objects] obj 
		ON obj.[object_id] = perm.[major_id]
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[schemas] s 
		ON s.[schema_id] = obj.[schema_id]
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[all_columns] c 
		ON c.[column_id] = perm.[minor_id]
	WHERE
		perm.[grantee_principal_id] IN ( SELECT [principal_id] FROM [' + @DatabaseName + '].[sys].[database_principals] WHERE [name] IN (''' + @RoleString + ''') ) 
		AND perm.[class] = 1
	UNION ALL';
	PRINT @UserRoleStmt;
	SET @UserRoleStmt = '
	/* [class] = 3 = Schema */
	SELECT
		@@SERVERNAME AS [ServerName],
		''' + @DatabaseName + ''' AS [Scope],
		prin.[name] AS [PrincipalName],
		perm.[class_desc] AS [ObjectType],
		perm.[permission_name] AS [PermissionType],
		perm.[state_desc] AS [PermissionState],
		s.[name] AS [SchemaName],
		''N/A'' AS [ObjectName],
		''N/A'' AS [ColumnName],
		GETDATE() AS [PollDate]
	FROM
		[' + @DatabaseName + '].[sys].[database_permissions] perm
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin 
		ON prin.[principal_id] = perm.[grantee_principal_id]
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[schemas] s 
		ON s.[schema_id] = perm.[major_id]
	WHERE
		perm.[grantee_principal_id] IN ( SELECT [principal_id] FROM [' + @DatabaseName + '].[sys].[database_principals] WHERE [name] IN (''' + @RoleString + ''') ) 
		AND perm.[class] = 3 /* 3 = Schema */
	UNION ALL';
	PRINT @UserRoleStmt;
	SET @UserRoleStmt = '
	/* [class] = 4 = DATABASE_PRINCIPAL */
	SELECT
		@@SERVERNAME AS [ServerName],
		''' + @DatabaseName + ''' AS [Scope],
		prin.[name] AS [PrincipalName],
		perm.[class_desc] AS [ObjectType],
		perm.[permission_name] AS [PermissionType],
		perm.[state_desc] AS [PermissionState],
		''N/A'' AS [SchemaName],
		prin1.[name] AS [ObjectName], 
		/* USER_NAME(prin.[principal_id]) AS [ObjectName], */
		''N/A'' AS [ColumnName],
		GETDATE() AS [PollDate]
	FROM
		[' + @DatabaseName + '].[sys].[database_permissions] perm
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin  
		ON prin.[principal_id] = perm.[grantee_principal_id]
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin1 
		ON prin1.[principal_id] = perm.[major_id]
	WHERE
		perm.[grantee_principal_id] IN ( SELECT [principal_id] FROM [' + @DatabaseName + '].[sys].[database_principals] WHERE [name] IN (''' + @RoleString + ''') ) 
		AND perm.[class] = 4 /* 4 = DATABASE_PRINCIPAL */
	UNION ALL';
	PRINT @UserRoleStmt;
	SET @UserRoleStmt = '
	/* [class] = 5 = Assembly */
	SELECT
		@@SERVERNAME AS [ServerName],
		''' + @DatabaseName + ''' AS [Scope],
		prin.[name] AS [PrincipalName],
		perm.[class_desc] AS [ObjectType],
		perm.[permission_name] AS [PermissionType],
		perm.[state_desc] AS [PermissionState],
		''N/A'' AS [SchemaName],
		USER_NAME(a.[name]) AS [ObjectName],
		''N/A'' AS [ColumnName],
		GETDATE() AS [PollDate]
	FROM
		[' + @DatabaseName + '].[sys].[database_permissions] perm
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin 
		ON prin.[principal_id] = perm.[grantee_principal_id]
	LEFT OUTER JOIN	[' + @DatabaseName + '].[sys].[assemblies] a 
		ON a.[principal_id] = perm.[major_id]
	WHERE
		perm.[grantee_principal_id] IN ( SELECT [principal_id] FROM [' + @DatabaseName + '].[sys].[database_principals] WHERE [name] IN (''' + @RoleString + ''') ) 
		AND perm.[class] = 5 /* 5 = Assembly */
	UNION ALL';
	PRINT @UserRoleStmt;
	SET @UserRoleStmt = '
	/* [class] = 6 = Type */
	SELECT
		@@SERVERNAME AS [ServerName],
		''' + @DatabaseName + ''' AS [Scope],
		prin.[name] AS [PrincipalName],
		perm.[class_desc] AS [ObjectType],
		perm.[permission_name] AS [PermissionType],
		perm.[state_desc] AS [PermissionState],
		''N/A'' AS [SchemaName],
		t.[name] AS [ObjectName],
		''N/A'' AS [ColumnName],
		GETDATE() AS [PollDate]
	FROM
		[' + @DatabaseName + '].[sys].[database_permissions] perm
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin 
		ON prin.[principal_id] = perm.[grantee_principal_id]
	LEFT OUTER JOIN	[' + @DatabaseName + '].[sys].[types] t 
		ON t.[user_type_id] = perm.[major_id]
	WHERE
		perm.[grantee_principal_id] IN ( SELECT [principal_id] FROM [' + @DatabaseName + '].[sys].[database_principals] WHERE [name] IN (''' + @RoleString + ''') ) 
		AND perm.[class] = 6 /* 6 = Type */
	UNION ALL';
	PRINT @UserRoleStmt;
	SET @UserRoleStmt = '
	/* [class] = 10 = XML Schema Collection */
	SELECT 
		@@SERVERNAME AS [ServerName],
		''' + @DatabaseName + ''' AS [Scope],
		prin.[name] AS [PrincipalName],
		perm.[class_desc] AS [ObjectType],
		perm.[permission_name] AS [PermissionType],
		perm.[state_desc] AS [PermissionState],
		''N/A'' AS [SchemaName],
		COALESCE(OBJECT_NAME(perm.[major_id]), ''Unknown'') AS [ObjectName],
		''N/A'' AS [ColumnName],
		GETDATE() AS [PollDate]
	FROM
		[' + @DatabaseName + '].[sys].[database_permissions] perm
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin 
			ON prin.[principal_id] = perm.[grantee_principal_id]
	WHERE
		perm.[grantee_principal_id] IN ( SELECT [principal_id] FROM [' + @DatabaseName + '].[sys].[database_principals] WHERE [name] IN (''' + @RoleString + ''') ) 
		AND perm.[class] = 10 /* 10 = XML Schema Collection Certificates */
	UNION ALL';
	PRINT @UserRoleStmt;
	SET @UserRoleStmt = '
	/* [class] = 25 = Certificates */
	SELECT 
		@@SERVERNAME AS [ServerName],
		''' + @DatabaseName + ''' AS [Scope],
		prin.[name] AS [PrincipalName],
		perm.[class_desc] AS [ObjectType],
		perm.[permission_name] AS [PermissionType],
		perm.[state_desc] AS [PermissionState],
		''N/A'' AS [SchemaName],
		COALESCE(cer.[name], ''Unknown'') AS [ObjectName],
		''N/A'' AS [ColumnName],
		GETDATE() AS [PollDate]
	FROM
		[' + @DatabaseName + '].[sys].[database_permissions] perm
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin 
		ON prin.[principal_id] = perm.[grantee_principal_id]
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[certificates] cer 
		ON cer.[certificate_id] = perm.[major_id]
	WHERE
		perm.[grantee_principal_id] IN ( SELECT [principal_id] FROM [' + @DatabaseName + '].[sys].[database_principals] WHERE [name] IN (''' + @RoleString + ''') ) 
		AND perm.[class] = 25 /* 25 = Certificates */
	UNION ALL';

	UPDATE #DatabaseName
	SET 
		[IsProcessed] = 1
	WHERE 
		[DatabaseName] = @DatabaseName;

	/* Cleave off last UNION ALL */
	IF ( SELECT COUNT([DatabaseName]) FROM #DatabaseName WHERE [IsProcessed] = 1 ) = ( SELECT COUNT([DatabaseName]) FROM #DatabaseName )
	BEGIN 
		SET @UserRoleStmt = SUBSTRING(@UserRoleStmt, 0, (LEN(@UserRoleStmt)-9));
		PRINT @UserRoleStmt;
	END
	ELSE 
	BEGIN
		PRINT @UserRoleStmt;
	END
END

/* Reset database name temp table */
UPDATE #DatabaseName
SET [IsProcessed] = 0;

/* Gather database object permissions */
WHILE EXISTS ( SELECT TOP 1 [DatabaseName] FROM #DatabaseName WHERE [IsProcessed] = 0 )
BEGIN
	DECLARE @DBStmt [nvarchar](max);
	
	SELECT TOP 1
		@DatabaseName = [DatabaseName]
	FROM 
		#DatabaseName 
	WHERE 
		[IsProcessed] = 0
	ORDER BY 
		[DatabaseName] ASC;

	SET @DBStmt = '
	/* [class] = 0 = Database */
	SELECT
		@@SERVERNAME AS [ServerName],
		''' + @DatabaseName + ''' AS [Scope],
		prin.[name] AS [PrincipalName],
		perm.[class_desc] AS [ObjectType],
		perm.[permission_name] AS [PermissionType],
		perm.[state_desc] AS [PermissionState],
		''N/A'' AS [SchemaName],
		''N/A'' AS [ObjectName],
		''N/A'' AS [ColumnName],
		GETDATE() AS [PollDate]
	FROM
		[' + @DatabaseName + '].[sys].[database_permissions] perm
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin 
		ON prin.[principal_id] = perm.[grantee_principal_id]
	WHERE
		perm.[grantee_principal_id] IN ( SELECT [principal_id] FROM [' + @DatabaseName + '].[sys].[database_principals] WHERE [name] IN (''' + @Public + ''',''' + @PrincipalOrRole + '' + ''',''' + @ADGroupString + ''') ) 
		AND perm.[class] = 0 /* 0 = DATABASE */ 
	UNION ALL';
	PRINT @DBStmt;
	SET @DBStmt = '
	/* [class] = 1 = Object or Column */
	SELECT
		@@SERVERNAME AS [ServerName],
		''' + @DatabaseName + '''  AS [Scope],
		prin.[name] AS [PrincipalName],
		ISNULL(obj.[type_desc], perm.[class_desc]) AS [ObjectType],
		perm.[permission_name] AS [PermissionType],
		perm.[state_desc] AS [PermissionState],
		ISNULL(s.[name], ''Unknown'') AS [SchemaName],
		COALESCE(obj.[name], OBJECT_NAME(perm.[major_id]), ''N/A'') AS [ObjectName],
		ISNULL(c.[name], ''N/A'') AS [ColumnName],
		GETDATE() AS [PollDate]
	FROM
		[' + @DatabaseName + '].[sys].[database_permissions] perm
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin 
		ON prin.[principal_id] = perm.[grantee_principal_id]
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[all_objects] obj 
		ON obj.[object_id] = perm.[major_id]
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[schemas] s 
		ON s.[schema_id] = obj.[schema_id]
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[all_columns] c 
		ON c.[column_id] = perm.[minor_id]
	WHERE
		perm.[grantee_principal_id] IN ( SELECT [principal_id] FROM [' + @DatabaseName + '].[sys].[database_principals] WHERE [name] IN (''' + @Public + ''',''' + @PrincipalOrRole + '' + ''',''' + @ADGroupString + ''') ) 
		AND perm.[class] = 1
	UNION ALL';
	PRINT @DBStmt;
	SET @DBStmt = '
	/* [class] = 3 = Schema */
	SELECT
		@@SERVERNAME AS [ServerName],
		''' + @DatabaseName + ''' AS [Scope],
		prin.[name] AS [PrincipalName],
		perm.[class_desc] AS [ObjectType],
		perm.[permission_name] AS [PermissionType],
		perm.[state_desc] AS [PermissionState],
		s.[name] AS [SchemaName],
		''N/A'' AS [ObjectName],
		''N/A'' AS [ColumnName],
		GETDATE() AS [PollDate]
	FROM
		[' + @DatabaseName + '].[sys].[database_permissions] perm
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin 
		ON prin.[principal_id] = perm.[grantee_principal_id]
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[schemas] s 
		ON s.[schema_id] = perm.[major_id]
	WHERE
		perm.[grantee_principal_id] IN ( SELECT [principal_id] FROM [' + @DatabaseName + '].[sys].[database_principals] WHERE [name] IN (''' + @Public + ''',''' + @PrincipalOrRole + '' + ''',''' + @ADGroupString + ''') ) 
		AND perm.[class] = 3 /* 3 = Schema */
	UNION ALL';
	PRINT @DBStmt;
	SET @DBStmt = '
	/* [class] = 4 = DATABASE_PRINCIPAL */
	SELECT
		@@SERVERNAME AS [ServerName],
		''' + @DatabaseName + ''' AS [Scope],
		prin.[name] AS [PrincipalName],
		perm.[class_desc] AS [ObjectType],
		perm.[permission_name] AS [PermissionType],
		perm.[state_desc] AS [PermissionState],
		''N/A'' AS [SchemaName],
		prin1.[name] AS [ObjectName], 
		/* USER_NAME(prin.[principal_id]) AS [ObjectName], */
		''N/A'' AS [ColumnName],
		GETDATE() AS [PollDate]
	FROM
		[' + @DatabaseName + '].[sys].[database_permissions] perm
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin  
		ON prin.[principal_id] = perm.[grantee_principal_id]
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin1 
		ON prin1.[principal_id] = perm.[major_id]
	WHERE
		perm.[grantee_principal_id] IN ( SELECT [principal_id] FROM [' + @DatabaseName + '].[sys].[database_principals] WHERE [name] IN (''' + @Public + ''',''' + @PrincipalOrRole + '' + ''',''' + @ADGroupString + ''') ) 
		AND perm.[class] = 4 /* 4 = DATABASE_PRINCIPAL */
	UNION ALL';
	PRINT @DBStmt;
	SET @DBStmt = '
	/* [class] = 5 = Assembly */
	SELECT
		@@SERVERNAME AS [ServerName],
		''' + @DatabaseName + ''' AS [Scope],
		prin.[name] AS [PrincipalName],
		perm.[class_desc] AS [ObjectType],
		perm.[permission_name] AS [PermissionType],
		perm.[state_desc] AS [PermissionState],
		''N/A'' AS [SchemaName],
		USER_NAME(a.[name]) AS [ObjectName],
		''N/A'' AS [ColumnName],
		GETDATE() AS [PollDate]
	FROM
		[' + @DatabaseName + '].[sys].[database_permissions] perm
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin 
		ON prin.[principal_id] = perm.[grantee_principal_id]
	LEFT OUTER JOIN	[' + @DatabaseName + '].[sys].[assemblies] a 
		ON a.[principal_id] = perm.[major_id]
	WHERE
		perm.[grantee_principal_id] IN ( SELECT [principal_id] FROM [' + @DatabaseName + '].[sys].[database_principals] WHERE [name] IN (''' + @Public + ''',''' + @PrincipalOrRole + '' + ''',''' + @ADGroupString + ''') ) 
		AND perm.[class] = 5 /* 5 = Assembly */
	UNION ALL';
	PRINT @DBStmt;
	SET @DBStmt = '
	/* [class] = 6 = Type */
	SELECT
		@@SERVERNAME AS [ServerName],
		''' + @DatabaseName + ''' AS [Scope],
		prin.[name] AS [PrincipalName],
		perm.[class_desc] AS [ObjectType],
		perm.[permission_name] AS [PermissionType],
		perm.[state_desc] AS [PermissionState],
		''N/A'' AS [SchemaName],
		t.[name] AS [ObjectName],
		''N/A'' AS [ColumnName],
		GETDATE() AS [PollDate]
	FROM
		[' + @DatabaseName + '].[sys].[database_permissions] perm
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin 
		ON prin.[principal_id] = perm.[grantee_principal_id]
	LEFT OUTER JOIN	[' + @DatabaseName + '].[sys].[types] t 
		ON t.[user_type_id] = perm.[major_id]
	WHERE
		perm.[grantee_principal_id] IN ( SELECT [principal_id] FROM [' + @DatabaseName + '].[sys].[database_principals] WHERE [name] IN (''' + @Public + ''',''' + @PrincipalOrRole + '' + ''',''' + @ADGroupString + ''') ) 
		AND perm.[class] = 6 /* 6 = Type */
	UNION ALL';
	PRINT @DBStmt;
	SET @DBStmt = '
	/* [class] = 10 = XML Schema Collection */
	SELECT 
		@@SERVERNAME AS [ServerName],
		''' + @DatabaseName + ''' AS [Scope],
		prin.[name] AS [PrincipalName],
		perm.[class_desc] AS [ObjectType],
		perm.[permission_name] AS [PermissionType],
		perm.[state_desc] AS [PermissionState],
		''N/A'' AS [SchemaName],
		COALESCE(OBJECT_NAME(perm.[major_id]), ''Unknown'') AS [ObjectName],
		''N/A'' AS [ColumnName],
		GETDATE() AS [PollDate]
	FROM
		[' + @DatabaseName + '].[sys].[database_permissions] perm
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin 
			ON prin.[principal_id] = perm.[grantee_principal_id]
	WHERE
		perm.[grantee_principal_id] IN ( SELECT [principal_id] FROM [' + @DatabaseName + '].[sys].[database_principals] WHERE [name] IN (''' + @Public + ''',''' + @PrincipalOrRole + '' + ''',''' + @ADGroupString + ''') ) 
		AND perm.[class] = 10 /* 10 = XML Schema Collection Certificates */
	UNION ALL';
	PRINT @DBStmt;
	SET @DBStmt = '
	/* [class] = 25 = Certificates */
	SELECT 
		@@SERVERNAME AS [ServerName],
		''' + @DatabaseName + ''' AS [Scope],
		prin.[name] AS [PrincipalName],
		perm.[class_desc] AS [ObjectType],
		perm.[permission_name] AS [PermissionType],
		perm.[state_desc] AS [PermissionState],
		''N/A'' AS [SchemaName],
		COALESCE(cer.[name], ''Unknown'') AS [ObjectName],
		''N/A'' AS [ColumnName],
		GETDATE() AS [PollDate]
	FROM
		[' + @DatabaseName + '].[sys].[database_permissions] perm
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[database_principals] prin 
		ON prin.[principal_id] = perm.[grantee_principal_id]
	LEFT OUTER JOIN [' + @DatabaseName + '].[sys].[certificates] cer 
		ON cer.[certificate_id] = perm.[major_id]
	WHERE
		perm.[grantee_principal_id] IN ( SELECT [principal_id] FROM [' + @DatabaseName + '].[sys].[database_principals] WHERE [name] IN (''' + @Public + ''',''' + @PrincipalOrRole + '' + ''',''' + @ADGroupString + ''') ) 
		AND perm.[class] = 25 /* 25 = Certificates */
	UNION ALL'

	UPDATE #DatabaseName
	SET 
		[IsProcessed] = 1
	WHERE 
		[DatabaseName] = @DatabaseName;

	/* Cleave off last UNION ALL */
	IF ( SELECT COUNT([DatabaseName]) FROM #DatabaseName WHERE [IsProcessed] = 1 ) = ( SELECT COUNT([DatabaseName]) FROM #DatabaseName )
	BEGIN 
		SET @DBStmt = SUBSTRING(@DBStmt, 0, (LEN(@DBStmt)-9));
		PRINT @DBStmt;
	END
	ELSE 
	BEGIN
		PRINT @DBStmt;
	END
END

/* Reset database name temp table */
UPDATE #DatabaseName
SET [IsProcessed] = 0;

/* Loop thru and check any rare securables as a catch-all */
WHILE EXISTS ( SELECT TOP 1 [DatabaseName] FROM #DatabaseName WHERE [IsProcessed] = 0 )
BEGIN
	DECLARE @RareSecurablesStmt [nvarchar](max);
	
	SELECT TOP 1
		@DatabaseName = [DatabaseName]
	FROM 
		#DatabaseName 
	WHERE 
		[IsProcessed] = 0
	ORDER BY 
		[DatabaseName] ASC;

	SET @RareSecurablesStmt = '
	SELECT
		@@SERVERNAME AS [ServerName],
		''' + @DatabaseName + ''' AS [Scope],
		prin.[name] AS [PrincipalName],
		perm.*
	FROM
		[' + @DatabaseName + '].[sys].[database_permissions] perm
		JOIN [' + @DatabaseName + '].[sys].[database_principals] prin 
			ON prin.[principal_id] = perm.[grantee_principal_id]
	WHERE
		prin.[name] IN (''' + @Public + ''',''' + @PrincipalOrRole + '' + ''',''' + @ADGroupString + ''') 
		AND perm.[class] NOT IN (0,1,3,4,5,6,10,25)
	UNION ALL';
	
	UPDATE #DatabaseName
	SET 
		[IsProcessed] = 1
	WHERE 
		[DatabaseName] = @DatabaseName;

	/* Cleave off last UNION ALL */
	IF ( SELECT COUNT([DatabaseName]) FROM #DatabaseName WHERE [IsProcessed] = 1 ) = ( SELECT COUNT([DatabaseName]) FROM #DatabaseName )
	BEGIN 
		SET @RareSecurablesStmt = SUBSTRING(@RareSecurablesStmt, 0, (LEN(@RareSecurablesStmt)-9));
		PRINT @RareSecurablesStmt;
	END
	ELSE 
		PRINT @RareSecurablesStmt;
END

END

DROP TABLE IF EXISTS #SysLogins;
DROP TABLE IF EXISTS #NtGroup;
DROP TABLE IF EXISTS #ADGroupMember;
DROP TABLE IF EXISTS #GroupLoop;
DROP TABLE IF EXISTS #PrincipalsADGroups;
DROP TABLE IF EXISTS #DatabaseName;
DROP TABLE IF EXISTS ##Role_7FF7C4A15E074DC899DC11BD248EB6C6;