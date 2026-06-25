package com.siteblocker.app;

import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.net.VpnService;
import android.os.Bundle;
import android.os.PowerManager;
import android.provider.Settings;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.*;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import org.json.JSONArray;
import org.json.JSONException;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    private static final int VPN_REQUEST_CODE = 100;
    private SharedPreferences prefs;
    private List<String> blockedSites;
    private SiteAdapter adapter;
    private Switch switchVpn;
    private TextView tvStatus;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        prefs = getSharedPreferences("siteblocker", MODE_PRIVATE);
        blockedSites = loadSites();

        // Ask Samsung to not kill our VPN service
        requestBatteryOptimizationExemption();

        RecyclerView rv = findViewById(R.id.recyclerView);
        rv.setLayoutManager(new LinearLayoutManager(this));
        adapter = new SiteAdapter(blockedSites);
        rv.setAdapter(adapter);

        switchVpn = findViewById(R.id.switchVpn);
        tvStatus = findViewById(R.id.tvStatus);
        FloatingActionButton fab = findViewById(R.id.fab);

        // Restore switch state
        boolean isRunning = prefs.getBoolean("vpn_running", false);
        switchVpn.setChecked(isRunning);
        updateStatusText(isRunning);

        switchVpn.setOnCheckedChangeListener((btn, checked) -> {
            if (checked) startVpn();
            else stopVpn();
        });

        fab.setOnClickListener(v -> showAddDialog());

        // Change PIN button
        findViewById(R.id.btnChangePin).setOnClickListener(v -> showChangePinDialog());
    }

    /** Ask Samsung to exempt this app from battery optimization so VPN keeps running. */
    private void requestBatteryOptimizationExemption() {
        PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
        if (!pm.isIgnoringBatteryOptimizations(getPackageName())) {
            Intent intent = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
            intent.setData(Uri.parse("package:" + getPackageName()));
            startActivity(intent);
        }
    }

    private void startVpn() {
        Intent intent = VpnService.prepare(this);
        if (intent != null) {
            startActivityForResult(intent, VPN_REQUEST_CODE);
        } else {
            onActivityResult(VPN_REQUEST_CODE, RESULT_OK, null);
        }
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (req == VPN_REQUEST_CODE && res == RESULT_OK) {
            Intent svc = new Intent(this, BlockerVpnService.class);
            svc.setAction(BlockerVpnService.ACTION_START);
            startService(svc);
            prefs.edit().putBoolean("vpn_running", true).apply();
            updateStatusText(true);
        } else {
            // User denied VPN permission
            switchVpn.setChecked(false);
            updateStatusText(false);
        }
    }

    private void stopVpn() {
        Intent svc = new Intent(this, BlockerVpnService.class);
        svc.setAction(BlockerVpnService.ACTION_STOP);
        startService(svc);
        prefs.edit().putBoolean("vpn_running", false).apply();
        updateStatusText(false);
    }

    private void updateStatusText(boolean running) {
        tvStatus.setText(running ? "🟢 Blocker is ON" : "🔴 Blocker is OFF");
    }

    private void showAddDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("Add Website to Block");
        EditText et = new EditText(this);
        et.setHint("e.g. youtube.com");
        et.setPadding(40, 20, 40, 20);
        builder.setView(et);
        builder.setPositiveButton("Add", (d, w) -> {
            String site = et.getText().toString().trim().toLowerCase()
                    .replace("https://", "").replace("http://", "").replace("www.", "");
            if (!site.isEmpty() && !blockedSites.contains(site)) {
                blockedSites.add(site);
                adapter.notifyItemInserted(blockedSites.size() - 1);
                saveSites();
                // Restart VPN to apply new list
                if (prefs.getBoolean("vpn_running", false)) {
                    stopVpn();
                    startVpn();
                }
            }
        });
        builder.setNegativeButton("Cancel", null);
        builder.show();
    }

    private void showChangePinDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("Change PIN");
        View view = LayoutInflater.from(this).inflate(R.layout.dialog_change_pin, null);
        builder.setView(view);
        EditText etOld = view.findViewById(R.id.etOldPin);
        EditText etNew = view.findViewById(R.id.etNewPin);
        EditText etConf = view.findViewById(R.id.etConfirmPin);
        builder.setPositiveButton("Change", (d, w) -> {
            String old = etOld.getText().toString().trim();
            String newPin = etNew.getText().toString().trim();
            String conf = etConf.getText().toString().trim();
            String saved = prefs.getString("pin", "");
            if (!old.equals(saved)) {
                Toast.makeText(this, "Old PIN is wrong", Toast.LENGTH_SHORT).show();
            } else if (newPin.length() != 6) {
                Toast.makeText(this, "New PIN must be 6 digits", Toast.LENGTH_SHORT).show();
            } else if (!newPin.equals(conf)) {
                Toast.makeText(this, "New PINs do not match", Toast.LENGTH_SHORT).show();
            } else {
                prefs.edit().putString("pin", newPin).apply();
                Toast.makeText(this, "PIN changed!", Toast.LENGTH_SHORT).show();
            }
        });
        builder.setNegativeButton("Cancel", null);
        builder.show();
    }

    private List<String> loadSites() {
        List<String> list = new ArrayList<>();
        String json = prefs.getString("blocked_sites", "[]");
        try {
            JSONArray arr = new JSONArray(json);
            for (int i = 0; i < arr.length(); i++) list.add(arr.getString(i));
        } catch (JSONException ignored) {}
        return list;
    }

    private void saveSites() {
        JSONArray arr = new JSONArray(blockedSites);
        prefs.edit().putString("blocked_sites", arr.toString()).apply();
    }

    // Adapter for the RecyclerView list of blocked sites
    class SiteAdapter extends RecyclerView.Adapter<SiteAdapter.VH> {
        private final List<String> items;
        SiteAdapter(List<String> items) { this.items = items; }

        @Override
        public VH onCreateViewHolder(ViewGroup parent, int viewType) {
            View v = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_site, parent, false);
            return new VH(v);
        }

        @Override
        public void onBindViewHolder(VH h, int pos) {
            h.tvSite.setText(items.get(pos));
            h.btnDelete.setOnClickListener(v -> {
                int p = h.getAdapterPosition();
                items.remove(p);
                notifyItemRemoved(p);
                saveSites();
                if (prefs.getBoolean("vpn_running", false)) {
                    stopVpn();
                    startVpn();
                }
            });
        }

        @Override
        public int getItemCount() { return items.size(); }

        class VH extends RecyclerView.ViewHolder {
            TextView tvSite;
            ImageButton btnDelete;
            VH(View v) {
                super(v);
                tvSite = v.findViewById(R.id.tvSite);
                btnDelete = v.findViewById(R.id.btnDelete);
            }
        }
    }
}
