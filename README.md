# Two factor SMS authentication for Apache Tomcat

If you want to add two-factor SMS authentication to your application you should do several following steps:
1. Clone repository and execute command `gradlew build`
2. Copy `sms-authentication.jar` from **repo_clone_folder/build/lib** folder to Tomcat **CATALINA_HOME/lib** folder or add task to your build script wich makes this operation
3. Configure your `<Context>` tag in **CATALINA_HOME/conf/server.xml** as in the following example:
4. Add table wich will contain generated codes. Table name should be the same as in example above. See in tag `<Realm>` parameter `codeTable`. Table structure should be:
   ```
   id:numeric - Primary Key
   user:string - Foreign Key to user table
   code:string
   dateFrom:timestamp
   dateTo:timestamp
   ```
   Fields `dateFrom` and `dateTo` use to define time period in wich code is valid.   
5. Add to your application a function to generate code, save it in database and send it via SMS
6. Ensure that this function can be called without authentication
7. Latest step. Update your login page as folowing:
... 1. Add field with name `j_code` 
... 2. Add button `Get code`
... 3. Link this button with function wich has been created in **step 5**

**Congradulations!** Now you have two-factor authentication with SMS in your application.
