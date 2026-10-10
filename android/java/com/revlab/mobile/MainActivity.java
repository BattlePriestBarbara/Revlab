package com.revlab.mobile;

import android.app.Activity;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.view.ViewGroup;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * The whole client: one WebView, one address bar.
 *
 * RevLab's workbench runs on the machine that owns the Ghidra install and the
 * USB-attached device; a phone cannot host it. What a phone can do is show the
 * dashboard -- the same pages, findings and reports, over the local network,
 * with the access code the desktop prints when you press "share". So this is a
 * viewer, not a second implementation: no analysis logic is duplicated and
 * nothing is uploaded anywhere.
 *
 * Typical address: http://192.168.1.5:8765/?t=THE-CODE
 * (127.0.0.1 works too, for a RevLab running on the phone itself.)
 *
 * One class per file, no nested and no anonymous classes -- and that is not a
 * style preference. The R8 that ships in build-tools aborts with a
 * NullPointerException on any class file carrying an InnerClasses attribute
 * (reproducible with `python android/check_toolchain.py`; it affects
 * build-tools 29 through 36 regardless of the JDK that runs it). A top-level
 * listener therefore costs nothing and keeps the d8 step working; nothing else
 * here depends on the constraint.
 */
public class MainActivity extends Activity {

    private static final String PREFS = "revlab";
    private static final String KEY_URL = "url";
    private static final String DEFAULT_URL = "http://127.0.0.1:8765/";

    private WebView web;
    private EditText address;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.parseColor("#0b1014"));

        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setPadding(dp(10), dp(6), dp(10), dp(6));
        bar.setBackgroundColor(Color.parseColor("#131b21"));

        TextView label = new TextView(this);
        label.setText("RevLab");
        label.setTextColor(Color.parseColor("#35d0ba"));
        label.setPadding(0, 0, dp(10), 0);
        bar.addView(label);

        address = new EditText(this);
        address.setSingleLine(true);
        address.setHint("http://192.168.1.5:8765/?t=访问码");
        address.setText(storedUrl());
        address.setTextColor(Color.parseColor("#e8f4ff"));
        address.setHintTextColor(Color.parseColor("#5a6b78"));
        address.setInputType(InputType.TYPE_TEXT_VARIATION_URI);
        bar.addView(address, new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        Button go = new Button(this);
        go.setText("连接");
        go.setOnClickListener(new ConnectListener(this));
        bar.addView(go);
        root.addView(bar);

        web = new WebView(this);
        WebSettings settings = web.getSettings();
        settings.setJavaScriptEnabled(true);   // the dashboard is a little JS
        settings.setDomStorageEnabled(true);
        settings.setLoadWithOverviewMode(true);
        settings.setUseWideViewPort(true);
        web.setWebViewClient(new WebViewClient());
        web.setWebChromeClient(new WebChromeClient());
        root.addView(web, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        setContentView(root);
        loadFromBar();
    }

    /** What the button does: load whatever the address bar holds. */
    void loadFromBar() {
        load(address.getText().toString());
    }

    private String storedUrl() {
        SharedPreferences prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        return prefs.getString(KEY_URL, DEFAULT_URL);
    }

    private void load(String url) {
        String trimmed = url == null ? "" : url.trim();
        if (trimmed.isEmpty()) {
            return;
        }
        if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
            trimmed = "http://" + trimmed;
        }
        address.setText(trimmed);
        getSharedPreferences(PREFS, MODE_PRIVATE)
                .edit().putString(KEY_URL, trimmed).apply();
        web.loadUrl(trimmed);
    }

    private int dp(int value) {
        return Math.round(getResources().getDisplayMetrics().density * value);
    }

    @Override
    public void onBackPressed() {
        if (web != null && web.canGoBack()) {
            web.goBack();
            return;
        }
        super.onBackPressed();
    }
}
