# sms-authentication
Two factor SMS authentication for Apache Tomcat

It works very simple. To start work you should do several following steps:
1. Clone repository and execute command gradlew build
2. Copy sms-authentication.jar to Tomcat "lib" folder (CATALINA_HOME/lib)
3. Configure your Context as well as on following example
   Example:
4. Add table which will contains generated codes. Table should be:
5. Add in your application function to generate code(save it in database) and send it via SMS
6. Ensure that this function can be called without authorization
7. Update your login page. Add field with name j_code. Also add button Get Code.
Congradulations! Now you have two-factor authentication with SMS in your application.
