import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.stream.Collectors;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

/**
 * VulnerableApp.java
 * * A sample class containing common security vulnerabilities
 * for educational and testing purposes.
 *
 * WARNING: DO NOT USE THIS CODE IN A PRODUCTION ENVIRONMENT.
 * It is intentionally insecure.
 */
public class VulnerableApp {

    // Dummy database connection for demonstration
    private Connection dbConnection; 

    public VulnerableApp(Connection conn) {
        this.dbConnection = conn;
    }

    // --- 1. SQL Injection --
    public ResultSet vulnerableSQLQuery(String userId) {
        try {
            Statement statement = dbConnection.createStatement();
            // VULNERABLE LINE: User input is directly part of the query
            String sql = "SELECT * FROM users WHERE userId = '" + userId + "'";
            System.out.println("Executing (vulnerable): " + sql);
            return statement.executeQuery(sql);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public ResultSet secureSQLQuery(String userId) {
        try {
            // SECURE: Query is pre-compiled, user input is treated as a parameter
            String sql = "SELECT * FROM users WHERE userId = ?";
            PreparedStatement preparedStatement = dbConnection.prepareStatement(sql);
            preparedStatement.setString(1, userId); // Input is safely bound
            
            System.out.println("Executing (secure): " + preparedStatement.toString());
            return preparedStatement.executeQuery();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // --- 2. Cross-Site Scripting----//
    public String vulnerableXSS(String comment) {
        // VULNERABLE: User input is directly reflected in the "HTML" response
        return "<html><body><h2>Latest Comment:</h2><p>" + comment + "</p></body></html>";
    }

    /**
     * [SECURE] Fixed Cross-Site Scripting (XSS)
     * This method "escapes" or "sanitizes" the user input before rendering it.
     * Special HTML characters are replaced with their entity equivalents,
     * so the browser renders them as text, not as executable code.
     */
    public String secureXSS(String comment) {
        // SECURE: Input is sanitized to prevent interpretation as HTML
        String sanitizedComment = escapeHTML(comment);
        return "<html><body><h2>Latest Comment:</h2><p>" + sanitizedComment + "</p></body></html>";
    }

    /**
     * A simple helper function to escape HTML.
     * Note: A robust library like OWASP Java Encoder is recommended 
     * for real-world applications.
     */
    private String escapeHTML(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;");
    }


    // --- 3. OS Command Injection ---

   
    public String vulnerableCommandInjection(String filename) {
        StringBuilder output = new StringBuilder();
        try {
            // VULNERABLE: User input is passed to a shell (/bin/sh -c)
            Process process = Runtime.getRuntime().exec("/bin/sh -c 'cat " + filename + "'");
            
            // Read output
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }
            process.waitFor();
        } catch (IOException | InterruptedException e) {
            return "Error: " + e.getMessage();
        }
        return output.toString();
    }

    /**
     * [SECURE] Fixed OS Command Injection
     * This method avoids the shell by passing arguments as an array.
     * The ProcessBuilder treats the user input (filename) as a single,
     * distinct argument for the 'cat' command, not as separate commands.
     */
    public String secureCommandInjection(String filename) {
        // A real-world fix would also include validation to ensure
        //
