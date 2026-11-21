package com.devmonitor.agent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Specifications in the exact shape the DevMonitor server validates
 * (services.validate_detected_specifications). Pure Java.
 */
public final class DeviceSpecs {
    public static final String UNAVAILABLE = "Unavailable";

    public String cpuName;
    public Integer cpuCores;
    public Long ramCapacityBytes;
    public Long ramUsageBytes;
    public final List<Storage> storage = new ArrayList<>();
    public final List<String> gpus = new ArrayList<>();
    public String motherboard;
    public String osName;
    public String osVersion;
    public final List<String> networkAdapters = new ArrayList<>();
    public final List<String> ipAddresses = new ArrayList<>();

    public static final class Storage {
        public final String name;
        public final long totalBytes;
        public final long availableBytes;

        public Storage(String name, long totalBytes, long availableBytes) {
            this.name = name;
            this.totalBytes = totalBytes;
            this.availableBytes = Math.min(availableBytes, totalBytes);
        }
    }

    public String toPayloadJson(String deviceName, String deviceType) {
        long storageTotal = 0;
        long storageAvailable = 0;
        StringBuilder storageJson = new StringBuilder("[");
        for (int i = 0; i < storage.size(); i++) {
            Storage item = storage.get(i);
            storageTotal += item.totalBytes;
            storageAvailable += item.availableBytes;
            if (i > 0) {
                storageJson.append(',');
            }
            storageJson.append("{\"name\":").append(quote(limit(item.name, 128)))
                .append(",\"total_bytes\":").append(item.totalBytes)
                .append(",\"available_bytes\":").append(item.availableBytes).append('}');
        }
        storageJson.append(']');
        List<String> gpuValues = gpus.isEmpty() ? Collections.singletonList(UNAVAILABLE) : gpus;
        List<String> adapterValues = networkAdapters.isEmpty() ? Collections.singletonList(UNAVAILABLE) : networkAdapters;
        return "{\"name\":" + quote(limit(deviceName, 120))
            + ",\"device_type\":" + quote(deviceType)
            + ",\"specifications\":{"
            + "\"cpu_name\":" + quote(limit(cpuName, 255))
            + ",\"cpu_cores\":" + (cpuCores == null ? "null" : cpuCores)
            + ",\"ram_capacity_bytes\":" + (ramCapacityBytes == null ? "null" : ramCapacityBytes)
            + ",\"ram_usage_bytes\":" + (ramUsageBytes == null ? "null" : ramUsageBytes)
            + ",\"storage_devices\":" + storageJson
            + ",\"storage_total_bytes\":" + storageTotal
            + ",\"storage_available_bytes\":" + storageAvailable
            + ",\"gpu_information\":" + quoteList(gpuValues, 255)
            + ",\"motherboard_brand\":" + quote(limit(motherboard, 120))
            + ",\"operating_system_name\":" + quote(limit(osName, 120))
            + ",\"operating_system_version\":" + quote(limit(osVersion, 255))
            + ",\"network_adapters\":" + quoteList(adapterValues, 128)
            + ",\"ip_addresses\":" + quoteList(ipAddresses, 45)
            + "}}";
    }

    /** Human-readable rows for the review screen. */
    public List<String[]> summary() {
        List<String[]> rows = new ArrayList<>();
        rows.add(new String[] {"Processor", orUnavailable(cpuName)});
        rows.add(new String[] {"CPU cores", cpuCores == null ? UNAVAILABLE : cpuCores.toString()});
        rows.add(new String[] {"Memory", gigabytes(ramCapacityBytes)});
        rows.add(new String[] {"Memory in use", gigabytes(ramUsageBytes)});
        StringBuilder storageText = new StringBuilder();
        for (Storage item : storage) {
            if (storageText.length() > 0) {
                storageText.append("; ");
            }
            storageText.append(item.name).append(": ").append(gigabytes(item.availableBytes))
                .append(" free of ").append(gigabytes(item.totalBytes));
        }
        rows.add(new String[] {"Storage", storageText.length() == 0 ? UNAVAILABLE : storageText.toString()});
        rows.add(new String[] {"Graphics", gpus.isEmpty() ? UNAVAILABLE : String.join(", ", gpus)});
        rows.add(new String[] {"Model", orUnavailable(motherboard)});
        rows.add(new String[] {"Operating system", orUnavailable(osName) + " " + orUnavailable(osVersion)});
        rows.add(new String[] {"Network", networkAdapters.isEmpty() ? UNAVAILABLE : String.join(", ", networkAdapters)});
        rows.add(new String[] {"IP addresses", ipAddresses.isEmpty() ? UNAVAILABLE : String.join(", ", ipAddresses)});
        return rows;
    }

    private static String orUnavailable(String value) {
        return value == null || value.trim().isEmpty() ? UNAVAILABLE : value;
    }

    private static String gigabytes(Long bytes) {
        return bytes == null ? UNAVAILABLE
            : String.format(Locale.US, "%.1f GB", bytes / 1024.0 / 1024.0 / 1024.0);
    }

    private static String limit(String value, int max) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim().replaceAll("\\p{Cntrl}", " ");
        if (trimmed.isEmpty()) {
            return null;
        }
        return trimmed.length() > max ? trimmed.substring(0, max) : trimmed;
    }

    private static String quoteList(List<String> values, int max) {
        StringBuilder json = new StringBuilder("[");
        int count = 0;
        for (String value : values) {
            String limited = limit(value, max);
            if (limited == null || count >= 64) {
                continue;
            }
            if (count++ > 0) {
                json.append(',');
            }
            json.append(quote(limited));
        }
        return json.append(']').toString();
    }

    static String quote(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder json = new StringBuilder("\"");
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"': json.append("\\\""); break;
                case '\\': json.append("\\\\"); break;
                case '\n': json.append("\\n"); break;
                case '\r': json.append("\\r"); break;
                case '\t': json.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        json.append(String.format(Locale.US, "\\u%04x", (int) c));
                    } else {
                        json.append(c);
                    }
            }
        }
        return json.append('"').toString();
    }
}
