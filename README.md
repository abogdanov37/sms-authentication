# Two factor SMS authentication for Apache Tomcat

If you want to add two-factor SMS authentication to your application you should do the following steps:
1. Clone this repository and execute command `gradlew build`
2. Copy `sms-authentication.jar` from **repo_clone_folder/build/lib** folder to Tomcat **CATALINA_HOME/lib** folder or add task to your build script wich makes this operation
3. Configure your `<Context>` tag in **CATALINA_HOME/conf/server.xml** as follows:
   ```
          <Realm xmlns="" className="io.codesolver.auth.SMSRealm" dataSourceName="xyz" localDataSource="true" roleNameCol="GROUP_NAME" userCredCol="USR_PASSWD" 
                 userNameCol="USR_NAME" userRoleTable="MTD_GROUPS" userTable="MTD_USERS" codeTable="MTD_CODE">
            ...
          </Realm>
          <Valve xmlns="" className="io.codesolver.SMSAuthenticator"/>
   ```
4. Add table wich will contain generated codes. Table name should be the same as in the above example. See attribute `codeTable` of tag `<Realm>`. Table structure should be:
   ```
   id:numeric - Primary Key
   user:string - Foreign Key to user table
   code:string
   dateFrom:timestamp
   dateTo:timestamp
   ```
   Fields `dateFrom` and `dateTo` are used to define time period in wich code is valid.   
5. Add to your application a function wich will generate code, save code to database and send code via SMS
6. Ensure that this function can be called without authentication
7. Latest step. Update your login page as folowing:
   * Add field with name `j_code` 
   * Add button `Get code`
   * Link this button with function wich has been created in **step 5**

**Congradulations!** Now you have two-factor authentication with SMS in your application.
