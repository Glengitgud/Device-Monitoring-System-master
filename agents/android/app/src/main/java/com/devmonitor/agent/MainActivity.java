package com.devmonitor.agent;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.text.InputType;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Single-screen flow:
 *   1. Opened from "Link this device" (devmonitor://enroll?...) or by pasting the link.
 *   2. Shows the server and everything detected; nothing is sent yet.
 *   3. "Register this device" submits once; errors are shown with a retry.
 */
public class MainActivity extends Activity {
    private static final int BACKGROUND = Color.rgb(13, 2, 33);
    private static final int SURFACE = Color.rgb(18, 6, 54);
    private static final int ACCENT = Color.rgb(52, 88, 168);
    private static final int MUTED = Color.rgb(182, 195, 209);
    private static final int ERROR = Color.rgb(252, 165, 165);
    private static final int SUCCESS = Color.rgb(74, 222, 128);

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private EnrollmentLink link;
    private DeviceSpecs specs;
    private TextView subtitle;
    private TextView details;
    private TextView status;
    private EditText linkInput;
    private EditText nameInput;
    private Button primary;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        buildInterface();
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    @Override
    protected void onDestroy() {
        worker.shutdownNow();
        super.onDestroy();
    }

    private void handleIntent(Intent intent) {
        Uri data = intent == null ? null : intent.getData();
        if (data != null) {
            useLink(data.toString());
        } else if (link == null) {
            showLinkPrompt(null);
        }
    }

    private void showLinkPrompt(String error) {
        link = null;
        specs = null;
        subtitle.setText("On this device, open the DevMonitor website, sign in, go to "
            + "“Link a Device” and tap “Link this device”. "
            + "You can also paste the link here.");
        linkInput.setVisibility(View.VISIBLE);
        details.setVisibility(View.GONE);
        nameInput.setVisibility(View.GONE);
        primary.setText("Continue");
        primary.setEnabled(true);
        primary.setOnClickListener(view -> useLink(linkInput.getText().toString()));
        setStatus(error, true);
    }

    private void useLink(String rawLink) {
        try {
            link = EnrollmentLink.parse(rawLink);
        } catch (EnrollmentException error) {
            showLinkPrompt(error.getMessage());
            return;
        }
        linkInput.setVisibility(View.GONE);
        subtitle.setText("Register this device with " + link.host()
            + "? Review the details below. Nothing is sent until you tap Register.");
        details.setVisibility(View.VISIBLE);
        details.setText("Collecting device details…");
        nameInput.setVisibility(View.GONE);
        primary.setText("Register this device");
        primary.setEnabled(false);
        setStatus(null, false);
        worker.execute(() -> {
            DeviceSpecs collected = SpecCollector.collect(getApplicationContext());
            runOnUiThread(() -> showReview(collected));
        });
    }

    private void showReview(DeviceSpecs collected) {
        if (isFinishing() || isDestroyed()) {
            return;
        }
        specs = collected;
        StringBuilder text = new StringBuilder();
        for (String[] row : collected.summary()) {
            text.append(row[0]).append(": ").append(row[1]).append('\n');
        }
        text.append("Device type: ").append(SpecCollector.deviceType(this));
        details.setText(text.toString());
        if (nameInput.getText().length() == 0) {
            nameInput.setText(SpecCollector.deviceName(this));
        }
        nameInput.setVisibility(View.VISIBLE);
        primary.setEnabled(true);
        primary.setOnClickListener(view -> register());
    }

    private void register() {
        String name = nameInput.getText().toString().trim();
        if (name.isEmpty()) {
            name = SpecCollector.deviceName(this);
        }
        String payload = specs.toPayloadJson(name, SpecCollector.deviceType(this));
        EnrollmentLink target = link;
        primary.setEnabled(false);
        setStatus("Registering…", false);
        worker.execute(() -> {
            try {
                EnrollmentClient.Result result = EnrollmentClient.submit(target, payload, "Android");
                runOnUiThread(() -> onRegistered(result));
            } catch (EnrollmentException error) {
                runOnUiThread(() -> {
                    setStatus(error.getMessage(), true);
                    primary.setEnabled(true);
                    primary.setText("Try again");
                });
            }
        });
    }

    private void onRegistered(EnrollmentClient.Result result) {
        if (isFinishing() || isDestroyed()) {
            return;
        }
        status.setTextColor(SUCCESS);
        status.setText("Registered “" + (result.name == null ? "this device" : result.name)
            + "”" + (result.assetTag == null ? "" : " (asset " + result.assetTag + ")")
            + ". Your DevMonitor dashboard is now available.");
        status.setVisibility(View.VISIBLE);
        nameInput.setEnabled(false);
        String dashboard = link.serverUrl + "/dashboard";
        primary.setText("Open dashboard");
        primary.setEnabled(true);
        primary.setOnClickListener(view -> {
            try {
                startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(dashboard)));
            } catch (ActivityNotFoundException error) {
                setStatus("No browser is available to open " + dashboard, true);
            }
        });
    }

    private void setStatus(String message, boolean isError) {
        status.setVisibility(message == null ? View.GONE : View.VISIBLE);
        status.setTextColor(isError ? ERROR : MUTED);
        status.setText(message == null ? "" : message);
    }

    // ------------------------------------------------------------------
    // Programmatic layout (no AndroidX dependencies)
    // ------------------------------------------------------------------

    private void buildInterface() {
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(BACKGROUND);
        scroll.setFillViewport(true);
        LinearLayout column = new LinearLayout(this);
        column.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(24);
        column.setPadding(pad, dp(40), pad, pad);
        scroll.addView(column);

        TextView eyebrow = text("DEVMONITOR", 12, Color.rgb(165, 191, 255), true);
        eyebrow.setLetterSpacing(0.12f);
        column.addView(eyebrow);
        column.addView(text("Device Agent", 28, Color.WHITE, true), spaced(dp(4)));
        subtitle = text("", 15, MUTED, false);
        column.addView(subtitle, spaced(dp(12)));

        linkInput = new EditText(this);
        linkInput.setHint("devmonitor://enroll?…");
        linkInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        styleInput(linkInput);
        column.addView(linkInput, spaced(dp(20)));

        details = text("", 14, Color.WHITE, false);
        details.setLineSpacing(dp(4), 1f);
        details.setPadding(dp(16), dp(16), dp(16), dp(16));
        details.setBackground(rounded(SURFACE, dp(14)));
        details.setTextIsSelectable(true);
        column.addView(details, spaced(dp(20)));

        nameInput = new EditText(this);
        nameInput.setHint("Device name");
        nameInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_WORDS);
        styleInput(nameInput);
        column.addView(nameInput, spaced(dp(16)));

        primary = new Button(this);
        primary.setAllCaps(false);
        primary.setTextColor(Color.WHITE);
        primary.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        primary.setBackground(rounded(ACCENT, dp(12)));
        primary.setMinHeight(dp(52));
        column.addView(primary, spaced(dp(20)));

        status = text("", 14, MUTED, false);
        status.setGravity(Gravity.CENTER_HORIZONTAL);
        column.addView(status, spaced(dp(14)));
        setContentView(scroll);
    }

    private TextView text(String value, int sizeSp, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextColor(color);
        view.setTextSize(TypedValue.COMPLEX_UNIT_SP, sizeSp);
        if (bold) {
            view.setTypeface(Typeface.DEFAULT_BOLD);
        }
        return view;
    }

    private void styleInput(EditText input) {
        input.setTextColor(Color.WHITE);
        input.setHintTextColor(Color.rgb(154, 168, 186));
        input.setSingleLine(true);
        input.setPadding(dp(14), dp(12), dp(14), dp(12));
        input.setBackground(rounded(SURFACE, dp(10)));
    }

    private GradientDrawable rounded(int color, int radius) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(color);
        drawable.setCornerRadius(radius);
        return drawable;
    }

    private LinearLayout.LayoutParams spaced(int top) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        params.topMargin = top;
        return params;
    }

    private int dp(int value) {
        return Math.round(TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP, value, getResources().getDisplayMetrics()));
    }
}
