package com.devmonitor.agent;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.regex.Pattern;

/**
 * A one-use registration hand-off created by "Link this device" on the website:
 * {@code devmonitor://enroll?server=https%3A%2F%2Fhost&token=...}.
 *
 * Pure Java (no Android APIs) so it can be tested on a desktop JVM.
 */
public final class EnrollmentLink {
    private static final Pattern TOKEN = Pattern.compile("[A-Za-z0-9_-]{40,64}");
    private static final String ENROLL_PATH = "/api/device-agent/enroll";

    public final String serverUrl;
    public final String token;

    private EnrollmentLink(String serverUrl, String token) {
        this.serverUrl = serverUrl;
        this.token = token;
    }

    public String submissionUrl() {
        return serverUrl + ENROLL_PATH;
    }

    public String host() {
        return URI.create(serverUrl).getRawAuthority();
    }

    public static EnrollmentLink parse(String link) throws EnrollmentException {
        URI uri;
        try {
            uri = new URI(link == null ? "" : link.trim());
        } catch (URISyntaxException error) {
            throw new EnrollmentException("That is not a DevMonitor registration link.");
        }
        if (!"devmonitor".equals(uri.getScheme()) || !"enroll".equals(uri.getHost())) {
            throw new EnrollmentException("That is not a DevMonitor registration link.");
        }
        String server = null;
        String token = null;
        String query = uri.getRawQuery();
        if (query != null) {
            for (String pair : query.split("&")) {
                int equals = pair.indexOf('=');
                if (equals < 0) {
                    continue;
                }
                String key = decode(pair.substring(0, equals));
                String value = decode(pair.substring(equals + 1));
                if ("server".equals(key)) {
                    server = value;
                } else if ("token".equals(key)) {
                    token = value;
                }
            }
        }
        String origin = validateServer(server);
        if (token == null || !TOKEN.matcher(token).matches()) {
            throw new EnrollmentException(
                "The registration link is incomplete. Create a new link on the website.");
        }
        return new EnrollmentLink(origin, token);
    }

    static String validateServer(String server) throws EnrollmentException {
        URI uri;
        try {
            uri = new URI(server == null ? "" : server);
        } catch (URISyntaxException error) {
            throw invalidServer();
        }
        String scheme = uri.getScheme();
        String host = uri.getHost();
        String path = uri.getRawPath();
        if (scheme == null
                || host == null
                || !("https".equals(scheme) || "http".equals(scheme))
                || uri.getRawUserInfo() != null
                || uri.getRawQuery() != null
                || uri.getRawFragment() != null
                || !(path == null || path.isEmpty() || "/".equals(path))) {
            throw invalidServer();
        }
        boolean local = "localhost".equals(host) || "127.0.0.1".equals(host)
            || "[::1]".equals(host) || "::1".equals(host);
        if ("http".equals(scheme) && !local) {
            throw new EnrollmentException("For your security the DevMonitor server must use HTTPS.");
        }
        return scheme + "://" + uri.getRawAuthority();
    }

    private static EnrollmentException invalidServer() {
        return new EnrollmentException(
            "The registration link does not contain a valid server address.");
    }

    private static String decode(String value) throws EnrollmentException {
        try {
            return URLDecoder.decode(value, "UTF-8");
        } catch (UnsupportedEncodingException | IllegalArgumentException error) {
            throw new EnrollmentException("That is not a DevMonitor registration link.");
        }
    }
}
