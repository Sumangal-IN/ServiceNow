package com.kits.servicenowAutoAssign;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.HttpCookie;
import java.net.HttpURLConnection;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.apache.log4j.Logger;
import org.apache.commons.lang3.StringUtils;

public class GetAction {

    final static Logger LOG = Logger.getLogger(GetAction.class);

    public static void send(String in_domain, String in_username, String in_password, String in_queueName, String in_assignedTo) throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {

            @Override
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            @Override
            public void checkClientTrusted(X509Certificate[] certs,
                    String authType) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] certs,
                    String authType) {
            }
        }};

        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc
                    .getSocketFactory());
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
        }

        HostnameVerifier allHostsValid = (String hostname, SSLSession session) -> true;

        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        String username;
        String password = in_password;
        if (in_domain != null) {
            username = in_domain + "\\" + in_username;
        } else {
            username = in_username;
        }

        String Location = "";

        Authenticator.setDefault(new MyAuthenticator(username, password));
        CookieManager cm = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        CookieHandler.setDefault(cm);

        URL url = new URL("https://kingfisher.service-now.com");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("GET");
        conn.connect();

        InputStream in = conn.getInputStream();
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(in));
        int status = conn.getResponseCode();
        LOG.info("Status = " + status);
        String key;
        LOG.info("Headers-------start-----");
        for (int i = 1; (key = conn.getHeaderFieldKey(i)) != null; i++) {
            if (key.equals("Location")) {
                Location = conn.getHeaderField(i);
            }
            LOG.info(key + ":" + conn.getHeaderField(i));
        }

        String cookies = "";
        for (HttpCookie hc : cm.getCookieStore().getCookies()) {
            cookies = cookies + hc.getName() + "=" + hc.getValue() + "; ";
        }
        LOG.info(cookies);

        LOG.info("Headers-------end-----");
        LOG.info("Content-------start-----");
        String inputLine;
        String content = "";
        while ((inputLine = reader.readLine()) != null) {
            content += inputLine;
        }
        LOG.info(content);
        LOG.info("Content-------end-----");
        in.close();

        LOG.info("New Location : " + Location);
        LOG.info("##########################################");

        url = new URL(Location);
        conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("GET");
        conn.connect();

        in = conn.getInputStream();
        reader = new BufferedReader(new InputStreamReader(in));
        status = conn.getResponseCode();
        LOG.info("Status = " + status);
        LOG.info("Headers-------start-----");
        for (int i = 1; (key = conn.getHeaderFieldKey(i)) != null; i++) {

            if (key.equals("Location")) {
                Location = conn.getHeaderField(i);
            }
            LOG.info(key + ":" + conn.getHeaderField(i));
        }
        LOG.info("Headers-------end-----");
        LOG.info("Content-------start-----");
        content = "";
        while ((inputLine = reader.readLine()) != null) {
            content += inputLine;
        }
        LOG.info(content);
        LOG.info("Content-------end-----");
        in.close();
        Location = Location
                .substring(Location.indexOf("sysparm_url=") + 12);
        Location = URLDecoder.decode(Location, "UTF-8");
        LOG.info("New Location : " + Location);
        LOG.info("##########################################");

        url = new URL(Location);
        conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("GET");
        conn.connect();

        in = conn.getInputStream();
        reader = new BufferedReader(new InputStreamReader(in));
        status = conn.getResponseCode();
        LOG.info("Status = " + status);
        LOG.info("Headers-------start-----");
        for (int i = 1; (key = conn.getHeaderFieldKey(i)) != null; i++) {

            if (key.equals("Location")) {
                Location = conn.getHeaderField(i);
            }
            LOG.info(key + ":" + conn.getHeaderField(i));
        }
        LOG.info("Headers-------end-----");
        LOG.info("Content-------start-----");
        content = "";
        while ((inputLine = reader.readLine()) != null) {
            content += inputLine;
        }
        LOG.info(content);
        LOG.info("Content-------end-----");
        in.close();

        LOG.info("New Location : " + Location);
        LOG.info("##########################################");

        url = new URL("https://fs.kfplc.com" + Location);
        conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("GET");
        conn.connect();

        in = conn.getInputStream();
        reader = new BufferedReader(new InputStreamReader(in));
        status = conn.getResponseCode();
        LOG.info("Status = " + status);
        LOG.info("Headers-------start-----");
        for (int i = 1; (key = conn.getHeaderFieldKey(i)) != null; i++) {
            LOG.info(key + ":" + conn.getHeaderField(i));
        }
        LOG.info("Headers-------end-----");
        LOG.info("Content-------start-----");
        content = "";
        while ((inputLine = reader.readLine()) != null) {
            content += inputLine;
        }
        LOG.info(content);
        LOG.info("Content-------end-----");
        in.close();

        int start = content.indexOf("action=");
        int end = content.indexOf("\"", start + 8);
        String actionURL = content.substring(start + 8, end);
        start = content.indexOf("SAMLResponse\" value=");
        end = content.indexOf("\"", start + 21);
        String SAMLResponse = content.substring(start + 21, end);
        start = content.indexOf("RelayState\" value=");
        end = content.indexOf("\"", start + 19);
        String RelayState = content.substring(start + 19, end);
        LOG.info("actionURL : " + actionURL);
        LOG.info("SAMLResponse : " + SAMLResponse);
        LOG.info("RelayState : " + RelayState);

        LOG.info("##########################################");
        url = new URL("https://kingfisher.service-now.com/navpage.do");
        conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Host", "kingfisher.service-now.com");
        conn.setRequestProperty("Connection", "keep-alive");
        conn.setRequestProperty("Cache-Control", "max-age=0");
        conn.setRequestProperty("Content-Type",
                "application/x-www-form-urlencoded");
        conn.setRequestProperty("Cookie", cookies);
        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.connect();

        String POST_PARAMS = "SAMLResponse="
                + URLEncoder.encode(SAMLResponse, "UTF-8");
        POST_PARAMS += "&RelayState="
                + URLEncoder.encode(RelayState, "UTF-8");
        LOG.info("POSTING form data : " + POST_PARAMS);

        OutputStream os = conn.getOutputStream();
        os.write(POST_PARAMS.getBytes());
        os.flush();
        os.close();

        in = conn.getInputStream();
        reader = new BufferedReader(new InputStreamReader(in));
        status = conn.getResponseCode();
        LOG.info("Status = " + status);
        LOG.info("Headers-------start-----");
        for (int i = 1; (key = conn.getHeaderFieldKey(i)) != null; i++) {
            LOG.info(key + ":" + conn.getHeaderField(i));
        }
        LOG.info("Headers-------end-----");
        LOG.info("Content-------start-----");
        while ((inputLine = reader.readLine()) != null) {
            LOG.info(inputLine);
        }
        LOG.info("Content-------end-----");
        in.close();

        LOG.info("##########################################");
        url = new URL(
                "https://kingfisher.service-now.com/sys_user_group_list.do?CSV&sysparm_default_export_fields=all&sysparm_query=name%3D" + in_queueName.replaceAll(" ", "%20") + "&sysparm_default_export_fields=all");
        conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Cookie", cookies);

        in = conn.getInputStream();
        reader = new BufferedReader(new InputStreamReader(in));
        status = conn.getResponseCode();
        LOG.info("Status = " + status);
        LOG.info("Headers-------start-----");
        for (int i = 1; (key = conn.getHeaderFieldKey(i)) != null; i++) {
            LOG.info(key + ":" + conn.getHeaderField(i));
        }
        LOG.info("Content-------start-----");
        ArrayList<String> group_lines = new ArrayList<>();
        while ((inputLine = reader.readLine()) != null) {
            LOG.info(inputLine);
            group_lines.add(inputLine);
        }
        LOG.info("Content-------end-----");
        in.close();

        if (group_lines.size() < 2) {
            LOG.info("No such group found : " + in_queueName);
            throw new Exception("No such group found : " + in_queueName);
        }

        int sys_id_pos = Arrays.asList(group_lines.get(0).split(",")).indexOf("\"sys_id\"");
        String sys_id_group = group_lines.get(1).split(",")[sys_id_pos];
        sys_id_group = sys_id_group.split("\"")[1];
        LOG.info("sys_id of group : " + sys_id_group);

        LOG.info("##########################################");
        url = new URL(
                "https://kingfisher.service-now.com/sys_user_list.do?CSV&sysparm_query=user_name%3D" + in_assignedTo.replaceAll(" ", "%20") + "%5Eu_primary_group%3D" + sys_id_group + "&sysparm_default_export_fields=all");
        conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Cookie", cookies);

        in = conn.getInputStream();
        reader = new BufferedReader(new InputStreamReader(in));
        status = conn.getResponseCode();
        LOG.info("Status = " + status);
        LOG.info("Headers-------start-----");
        for (int i = 1; (key = conn.getHeaderFieldKey(i)) != null; i++) {
            LOG.info(key + ":" + conn.getHeaderField(i));
        }
        LOG.info("Content-------start-----");
        ArrayList<String> user_lines = new ArrayList<>();
        while ((inputLine = reader.readLine()) != null) {
            LOG.info(inputLine);
            user_lines.add(inputLine);
        }
        LOG.info("Content-------end-----");
        in.close();

        if (user_lines.size() < 2) {
            LOG.info("No such user found : " + in_assignedTo);
            throw new Exception("No such user found : " + in_assignedTo);
        }

        sys_id_pos = Arrays.asList(user_lines.get(0).split(",")).indexOf("\"sys_id\"");
        String sys_id_user = user_lines.get(1).split(",")[sys_id_pos];
        sys_id_user = sys_id_user.split("\"")[1];
        LOG.info("sys_id of user : " + sys_id_user);

        LOG.info("##########################################");
        url = new URL(
                "https://kingfisher.service-now.com/incident.do?CSV&sysparm_query=active%3Dtrue%5EstateNOT%20IN6%2C7%2C10%5Eu_type%3Dincident%5EORu_type%3Drequest%5Eassignment_group%3D" + sys_id_group + "%5Eassigned_toISEMPTY&sysparm_default_export_fields=all");
        conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Cookie", cookies);

        in = conn.getInputStream();
        reader = new BufferedReader(new InputStreamReader(in));
        status = conn.getResponseCode();
        LOG.info("Status = " + status);
        LOG.info("Headers-------start-----");
        for (int i = 1; (key = conn.getHeaderFieldKey(i)) != null; i++) {
            LOG.info(key + ":" + conn.getHeaderField(i));
        }
        LOG.info("Content-------start-----");
        ArrayList<String> incident_lines = new ArrayList<>();
        content = "";
        while ((inputLine = reader.readLine()) != null) {
            if (content.endsWith("\"") && inputLine.startsWith("\"")) {
                LOG.info(content);
                incident_lines.add(content);
                content = "";
            }
            content += inputLine;
        }
        LOG.info(content);
        incident_lines.add(content);
        LOG.info("Content-------end-----");
        in.close();

        if (incident_lines.size() < 2) {
            LOG.info("No unassigned incident");
        } else {
            sys_id_pos = Arrays.asList(incident_lines.get(0).split(",")).indexOf("\"sys_id\"");
            int inc_number = Arrays.asList(incident_lines.get(0).split(",")).indexOf("\"number\"");
            String sys_id_incident = "";
            String incident_number = "";
            String assignment_json_data = "{\"fields\":[{\"sys_mandatory\":false,\"visible\":true,\"dependentField\":\"assignment_group\",\"dbType\":12,\"label\":\"Assigned to\",\"sys_readonly\":false,\"type\":\"reference\",\"mandatory\":false,\"refTable\":\"sys_user\",\"displayValue\":\"" + in_assignedTo.toUpperCase() + "\",\"readonly\":false,\"hint\":\"Person primarily responsible for working this event\",\"name\":\"assigned_to\",\"attributes\":{},\"reference_key\":\"sys_id\",\"reference_qual\":\"active=true^u_support_group!=true^numberINitil,kingfisher_ag,kingfisher_sd,kingfisher_problem_user,kf_incident_user\",\"choice\":0,\"choices\":{},\"value\":\"" + sys_id_user + "\",\"max_length\":32,\"ed\":{\"reference\":\"sys_user\",\"dependent_value\":\"" + sys_id_group + "\",\"searchField\":\"user_name\",\"name\":\"assigned_to\",\"dependent_table\":\"sys_user_group\"},\"isInitialized\":true}],\"encoded_record\":\"\"}";
            LOG.info("Assignment JSON data : " + assignment_json_data);
            for (int i = 1; i < incident_lines.size(); i++) {
                StringBuilder incident_line = new StringBuilder(incident_lines.get(i));
                boolean double_quote = false;
                for (int a = 0; a < incident_line.length(); a++) {
                    if (incident_line.charAt(a) == ',') {
                        if (double_quote) {
                            incident_line.setCharAt(a, ' ');
                        }
                    }
                    if (incident_line.charAt(a) == '"') {
                        double_quote = (double_quote != true);
                    }
                }
                sys_id_incident = incident_line.toString().split(",")[sys_id_pos];
                sys_id_incident = sys_id_incident.split("\"")[1];
                incident_number = incident_line.toString().split(",")[inc_number];
                incident_number = incident_number.split("\"")[1];

                LOG.info("##########################################");
                LOG.info("Assigning incident : " + incident_number + " (" + sys_id_incident + ")");
                url = new URL(
                        "https://kingfisher.service-now.com/angular.do?sysparm_type=ui_action&method=execute&type=form&operation=update&action_id=0f57c2c96f5362001c62a005eb3ee410&table=incident&sys_id=" + sys_id_incident + "&save_parms=%7B%7D");
                conn = (HttpURLConnection) url.openConnection();
                conn.setInstanceFollowRedirects(false);
                conn.setRequestMethod("GET");
                conn.setRequestProperty("Cookie", cookies);
                status = conn.getResponseCode();
                LOG.info("Status = " + status);
                LOG.info("Headers-------start-----");
                String X_UserToken = null;
                for (int j = 1; (key = conn.getHeaderFieldKey(j)) != null; j++) {
                    LOG.info(key + ":" + conn.getHeaderField(j));
                    if (key.equals("X-UserToken-Response")) {
                        X_UserToken = conn.getHeaderField(j);
                    }
                }
                if (X_UserToken == null) {
                    throw new Exception("Invalid login");
                }
                LOG.info("##########################################");
                url = new URL("https://kingfisher.service-now.com/angular.do?sysparm_type=ui_action&method=execute&type=form&operation=update&action_id=0f57c2c96f5362001c62a005eb3ee410&table=incident&sys_id=" + sys_id_incident + "&save_parms=%7B%7D");
                conn = (HttpURLConnection) url.openConnection();
                conn.setInstanceFollowRedirects(false);
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Accept-Encoding", "deflate, br");
                conn.setRequestProperty("Cookie", cookies);
                conn.setRequestProperty("X-UserToken", X_UserToken);
                conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
                conn.setDoOutput(true);
                conn.setDoInput(true);
                conn.connect();

                os = conn.getOutputStream();
                os.write(assignment_json_data.getBytes("UTF-8"));
                os.flush();
                os.close();

                for (HttpCookie hc : cm.getCookieStore().getCookies()) {
                    LOG.info(hc.getName() + "=" + hc.getValue());
                }

                in = conn.getInputStream();
                reader = new BufferedReader(new InputStreamReader(in));
                status = conn.getResponseCode();
                LOG.info("Status = " + status);
                LOG.info("Headers-------start-----");
                for (int j = 1; (key = conn.getHeaderFieldKey(j)) != null; j++) {
                    LOG.info(key + ":" + conn.getHeaderField(j));
                }
                LOG.info("Headers-------end-----");
                LOG.info("Content-------start-----");
                content = "";
                while ((inputLine = reader.readLine()) != null) {
                    content += inputLine;
                }
                LOG.info(content);
                LOG.info("Content-------end-----");
                in.close();
                if (content.indexOf(sys_id_incident) > 0) {
                    LOG.info("Incident assigned successfully");
                } else {
                    LOG.info("Failed to assign the incident");
                }
            }
        }
        LOG.info("Finished");
    }

    static class MyAuthenticator extends Authenticator {

        private final String username;
        private final String password;

        public MyAuthenticator(String user, String pass) {
            username = user;
            password = pass;
        }

        @Override
        protected PasswordAuthentication getPasswordAuthentication() {
            LOG.info("Requesting Host  : " + getRequestingHost());
            LOG.info("Requesting Port  : " + getRequestingPort());
            LOG.info("Requesting Prompt : " + getRequestingPrompt());
            LOG.info("Requesting Protocol: "
                    + getRequestingProtocol());
            LOG.info("Requesting Scheme : " + getRequestingScheme());
            LOG.info("Requesting Site  : " + getRequestingSite());
            return new PasswordAuthentication(username, password.toCharArray());
        }
    }

    public static void main(String args[]) {
        try {
            LOG.info("Started");
            if (args.length < 6) {
                System.out.println("Invalid arguments");
                System.out.println("AutoAssign <domain> <username> <password> <group name> <assign to> <interval>");
            } else {
                while (true) {
                    LOG.info("Domain: " + args[0]);
                    LOG.info("Username: " + args[1]);
                    LOG.info("Password: " + StringUtils.repeat("*", args[2].length()));
                    LOG.info("Group name: " + args[3]);
                    LOG.info("Assign to: " + args[4]);
                    LOG.info("Interval: " + args[5] + " Seconds");
                    GetAction.send(args[0], args[1], args[2], args[3], args[4]);
                    Thread.sleep(Integer.parseInt(args[5]) * 1000);
                }
            }
        } catch (Exception ex) {
            LOG.error("Sorry, something wrong!", ex);
        }
    }
}
