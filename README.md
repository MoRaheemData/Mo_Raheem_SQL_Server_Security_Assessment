# Mo_Raheem_SQL_Server_Security_Assessment
Mo_Raheem_SQL_Server_Security_Assessment

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
