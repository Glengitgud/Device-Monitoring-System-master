package com.devmonitor.agent;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLException;

/** Submits a registration to POST /api/device-agent/enroll. Pure Java. */
public final class EnrollmentClient {
    public static final String VERSION = "1.0.0";

    public static final class Result {
        public final String name;
        public final String assetTag;

        Result(String name, String assetTag) {
            this.name = name;
            this.assetTag = assetTag;
        }
    }

    private EnrollmentClient() {
    }

    public static Result submit(EnrollmentLink link, String payloadJson, String platform)
            throws EnrollmentException {
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) new URL(link.submissionUrl()).openConnection();
            connection.setConnectTimeout(15000);
            connection.setReadTimeout(20000);
            connection.setInstanceFollowRedirects(false);
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Authorization", "Bearer " + link.token);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("User-Agent", "DevMonitorAgent/" + VERSION + " (" + platform + ")");
            byte[] body = payloadJson.getBytes(StandardCharsets.UTF_8);
            connection.setFixedLengthStreamingMode(body.length);
            try (OutputStream output = connection.getOutputStream()) {
                output.write(body);
            }
            int code = connection.getResponseCode();
            String response = read(code >= 400 ? connection.getErrorStream() : connection.getInputStream());
            if (code == 200 || code == 201) {
                return new Result(jsonString(response, "name"), jsonString(response, "asset_tag"));
            }
            if (code == 401) {
                throw new EnrollmentException(
                    "This registration link has expired or was already used. "
                        + "Create a new one on the DevMonitor website and try again.");
            }
            String message = jsonString(response, "error");
            throw new EnrollmentException(message != null ? message
                : "The server rejected the registration (HTTP " + code + ").");
        } catch (SSLException error) {
            throw new EnrollmentException(
                "The secure connection to " + link.host() + " could not be verified.");
        } catch (IOException error) {
            throw new EnrollmentException(
                "Could not reach the DevMonitor server at " + link.host()
                    + ". Check your internet connection and try again.");
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private static String read(InputStream stream) throws IOException {
        if (stream == null) {
            return "";
        }
        try (InputStream input = stream) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            int read;
            while ((read = input.read(chunk)) != -1 && buffer.size() < 65536) {
                buffer.write(chunk, 0, read);
            }
            return buffer.toString("UTF-8");
        }
    }

    /** Minimal reader for a top-level string field in the server's small JSON replies. */
    static String jsonString(String json, String key) {
        Matcher matcher = Pattern.compile(
            "\"" + Pattern.quote(key) + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(json);
        if (!matcher.find()) {
            return null;
        }
        String raw = matcher.group(1);
        StringBuilder value = new StringBuilder();
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '\\' && i + 1 < raw.length()) {
                char next = raw.charAt(++i);
                if (next == 'u' && i + 4 < raw.length()) {
                    value.append((char) Integer.parseInt(raw.substring(i + 1, i + 5), 16));
                    i += 4;
                } else if (next == 'n') {
                    value.append('\n');
                } else {
                    value.append(next);
                }
            } else {
                value.append(c);
            }
        }
        return value.toString();
    }
}
