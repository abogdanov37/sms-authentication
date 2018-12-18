package io.codesolver.auth;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.realm.DataSourceRealm;

import java.security.Principal;
import java.sql.*;
import java.util.Date;

public class SMSRealm extends DataSourceRealm {

    protected String codeTable;
    protected String preparedCode;

    public Principal authenticate(String username, String credentials, String code) {
        Principal principal = super.authenticate(username, credentials);
        return checkCode(username, code) ? principal : null;
    }

    private boolean checkCode(String username, String code) {
        if (code != null && !code.isEmpty()) {
            Connection dbConnection = open();
            if (dbConnection != null) {
                try {
                    String dbCode = getCode(dbConnection, username, new Date());
                    return code.equals(dbCode);
                } finally {
                    close(dbConnection);
                }
            }
        }
        return false;
    }

    public String getCodeTable() {
        return codeTable;
    }

    public void setCodeTable(String codeTable) {
        this.codeTable = codeTable;
    }

    @Override
    protected void startInternal() throws LifecycleException {

        // Create the code PreparedStatement string
        StringBuilder temp = new StringBuilder("SELECT Code FROM ");
        temp.append(codeTable);
        temp.append(" WHERE usr_name = ? and dateFrom <= ? and dateTo > ?");
        preparedCode = temp.toString();

        super.startInternal();
    }

    private PreparedStatement code(Connection dbConnection, String username, Date ta)
            throws SQLException {
        Timestamp point = new Timestamp(ta.getTime());
        PreparedStatement code = dbConnection.prepareStatement(preparedCode);
        code.setString(1, username);
        code.setTimestamp(2, point);
        code.setTimestamp(3, point);
        return (code);
    }

    protected String getCode(Connection dbConnection, String username, Date ta) {
        String code = null;
        try (PreparedStatement stmt = code(dbConnection, username, ta);
             ResultSet rs = stmt.executeQuery()) {
            if (rs.next()) {
                code = rs.getString(1);
            }
            return (code != null) ? code.trim() : null;
        } catch (SQLException e) {
            containerLog.error(
                    sm.getString("dataSourceRealm.getCode.exception",
                            username), e);
        }
        return null;
    }
}
