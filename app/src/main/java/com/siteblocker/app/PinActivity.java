package com.siteblocker.app;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;

/**
 * First screen. Handles PIN setup (first run) and PIN verify (subsequent runs).
 */
public class PinActivity extends AppCompatActivity {

    private SharedPreferences prefs;
    private EditText etPin, etConfirm;
    private TextView tvTitle, tvSubtitle;
    private Button btnAction;
    private boolean isSetup;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_pin);

        prefs = getSharedPreferences("siteblocker", MODE_PRIVATE);
        isSetup = !prefs.contains("pin");

        etPin = findViewById(R.id.etPin);
        etConfirm = findViewById(R.id.etConfirm);
        tvTitle = findViewById(R.id.tvTitle);
        tvSubtitle = findViewById(R.id.tvSubtitle);
        btnAction = findViewById(R.id.btnAction);

        if (isSetup) {
            tvTitle.setText("Set Your PIN");
            tvSubtitle.setText("Choose a 6-digit PIN to protect this app");
            etConfirm.setVisibility(View.VISIBLE);
            btnAction.setText("Set PIN");
        } else {
            tvTitle.setText("Site Blocker");
            tvSubtitle.setText("Enter your 6-digit PIN");
            etConfirm.setVisibility(View.GONE);
            btnAction.setText("Unlock");
        }

        btnAction.setOnClickListener(v -> {
            if (isSetup) handleSetup();
            else handleVerify();
        });
    }

    private void handleSetup() {
        String pin = etPin.getText().toString().trim();
        String confirm = etConfirm.getText().toString().trim();

        if (pin.length() != 6) {
            Toast.makeText(this, "PIN must be exactly 6 digits", Toast.LENGTH_SHORT).show();
            return;
        }
        if (!pin.equals(confirm)) {
            Toast.makeText(this, "PINs do not match", Toast.LENGTH_SHORT).show();
            return;
        }
        prefs.edit().putString("pin", pin).apply();
        openMain();
    }

    private void handleVerify() {
        String entered = etPin.getText().toString().trim();
        String saved = prefs.getString("pin", "");
        if (entered.equals(saved)) {
            openMain();
        } else {
            Toast.makeText(this, "Wrong PIN", Toast.LENGTH_SHORT).show();
            etPin.setText("");
        }
    }

    private void openMain() {
        startActivity(new Intent(this, MainActivity.class));
        finish();
    }
}
