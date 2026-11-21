package com.devmonitor.agent;

import android.app.ActivityManager;
import android.content.Context;
import android.opengl.EGL14;
import android.opengl.EGLConfig;
import android.opengl.EGLContext;
import android.opengl.EGLDisplay;
import android.opengl.EGLSurface;
import android.opengl.GLES20;
import android.os.Build;
import android.os.Environment;
import android.os.StatFs;
import android.provider.Settings;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collections;

/**
 * Collects what Android exposes to a normal app without special permissions.
 * Android 10+ hides the hardware MAC address from apps, so it is not reported.
 */
final class SpecCollector {
    private SpecCollector() {
    }

    static DeviceSpecs collect(Context context) {
        DeviceSpecs specs = new DeviceSpecs();
        specs.cpuName = safe(SpecCollector::cpuName);
        specs.cpuCores = Runtime.getRuntime().availableProcessors();

        ActivityManager activityManager =
            (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        if (activityManager != null) {
            ActivityManager.MemoryInfo memory = new ActivityManager.MemoryInfo();
            activityManager.getMemoryInfo(memory);
            specs.ramCapacityBytes = memory.totalMem;
            specs.ramUsageBytes = Math.max(0, memory.totalMem - memory.availMem);
        }

        try {
            StatFs stat = new StatFs(Environment.getDataDirectory().getPath());
            specs.storage.add(new DeviceSpecs.Storage(
                "Internal storage", stat.getTotalBytes(), stat.getAvailableBytes()));
        } catch (IllegalArgumentException ignored) {
            // Storage stays empty and is shown as unavailable.
        }

        String gpu = safe(SpecCollector::gpuRenderer);
        if (gpu != null) {
            specs.gpus.add(gpu);
        }
        specs.motherboard = (capitalize(Build.MANUFACTURER) + " " + Build.MODEL).trim();
        specs.osName = "Android";
        specs.osVersion = Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT + ")";
        collectNetwork(specs);
        return specs;
    }

    static String deviceType(Context context) {
        return context.getResources().getConfiguration().smallestScreenWidthDp >= 600
            ? "Tablet" : "Phone";
    }

    static String deviceName(Context context) {
        String name = Settings.Global.getString(context.getContentResolver(), Settings.Global.DEVICE_NAME);
        return name == null || name.trim().isEmpty() ? Build.MODEL : name.trim();
    }

    private static String cpuName() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            String model = Build.SOC_MODEL;
            String vendor = Build.SOC_MANUFACTURER;
            if (model != null && !Build.UNKNOWN.equals(model)) {
                return (vendor != null && !Build.UNKNOWN.equals(vendor) ? vendor + " " : "") + model;
            }
        }
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/cpuinfo"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("Hardware") && line.contains(":")) {
                    return line.substring(line.indexOf(':') + 1).trim();
                }
            }
        } catch (IOException ignored) {
            // Fall back to the board identifier below.
        }
        return Build.HARDWARE;
    }

    /** Reads GL_RENDERER from a 1x1 off-screen OpenGL ES context. */
    private static String gpuRenderer() {
        EGLDisplay display = EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY);
        int[] version = new int[2];
        if (display == EGL14.EGL_NO_DISPLAY || !EGL14.eglInitialize(display, version, 0, version, 1)) {
            return null;
        }
        EGLContext context = EGL14.EGL_NO_CONTEXT;
        EGLSurface surface = EGL14.EGL_NO_SURFACE;
        try {
            int[] attributes = {
                EGL14.EGL_RENDERABLE_TYPE, EGL14.EGL_OPENGL_ES2_BIT,
                EGL14.EGL_SURFACE_TYPE, EGL14.EGL_PBUFFER_BIT,
                EGL14.EGL_NONE,
            };
            EGLConfig[] configs = new EGLConfig[1];
            int[] count = new int[1];
            if (!EGL14.eglChooseConfig(display, attributes, 0, configs, 0, 1, count, 0) || count[0] == 0) {
                return null;
            }
            context = EGL14.eglCreateContext(display, configs[0], EGL14.EGL_NO_CONTEXT,
                new int[] {EGL14.EGL_CONTEXT_CLIENT_VERSION, 2, EGL14.EGL_NONE}, 0);
            surface = EGL14.eglCreatePbufferSurface(display, configs[0],
                new int[] {EGL14.EGL_WIDTH, 1, EGL14.EGL_HEIGHT, 1, EGL14.EGL_NONE}, 0);
            if (context == EGL14.EGL_NO_CONTEXT || surface == EGL14.EGL_NO_SURFACE
                    || !EGL14.eglMakeCurrent(display, surface, surface, context)) {
                return null;
            }
            String renderer = GLES20.glGetString(GLES20.GL_RENDERER);
            return renderer == null || renderer.trim().isEmpty() ? null : renderer.trim();
        } finally {
            EGL14.eglMakeCurrent(display, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_CONTEXT);
            if (surface != EGL14.EGL_NO_SURFACE) {
                EGL14.eglDestroySurface(display, surface);
            }
            if (context != EGL14.EGL_NO_CONTEXT) {
                EGL14.eglDestroyContext(display, context);
            }
            EGL14.eglTerminate(display);
        }
    }

    private static void collectNetwork(DeviceSpecs specs) {
        try {
            for (NetworkInterface network : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!network.isUp() || network.isLoopback()) {
                    continue;
                }
                specs.networkAdapters.add(network.getName());
                for (InetAddress address : Collections.list(network.getInetAddresses())) {
                    if (address.isLoopbackAddress() || address.isLinkLocalAddress()
                            || address.isAnyLocalAddress()) {
                        continue;
                    }
                    String text = address.getHostAddress();
                    if (text == null) {
                        continue;
                    }
                    int scope = text.indexOf('%');
                    if (scope >= 0) {
                        text = text.substring(0, scope);
                    }
                    if (!specs.ipAddresses.contains(text)) {
                        specs.ipAddresses.add(text);
                    }
                }
            }
        } catch (SocketException | NullPointerException ignored) {
            // Network details stay unavailable.
        }
    }

    private interface Probe {
        String read() throws Exception;
    }

    private static String safe(Probe probe) {
        try {
            return probe.read();
        } catch (Exception | LinkageError error) {
            return null;
        }
    }

    private static String capitalize(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        return Character.toUpperCase(value.charAt(0)) + value.substring(1);
    }
}
