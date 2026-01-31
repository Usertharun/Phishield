import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

/* ================= GLOBAL APP STATE ================= */

class AppState {
  static bool barrierOn = false;
  static String language = "en";
}

/* ================= NETWORK STATE ================= */

class NetworkState {
  static bool wifiProtection = true;
  static bool vpnDetection = true;
  static bool dnsProtection = true;
}

/* ================= SETTINGS STATE ================= */

class SettingsState {
  static bool realtimeProtection = true;
  static bool safeBrowsing = true;
  static bool voiceAlerts = true;
}

/* ================= UI LANGUAGE MAP ================= */

Map<String, Map<String, String>> uiLang = {
  "en": {
    "scan": "Scan Link",
    "protected": "Protected",
    "barrier": "Barrier Active",
    "settings": "Settings",
    "risk": "Risk Score",
    "why": "Why this link was flagged",
    "network": "Network Protection",
    "apk": "APK Scanner",
    "history": "Threat History",
  },
  "ta": {
    "scan": "இணைப்பை சரிபார்",
    "protected": "பாதுகாப்பாக உள்ளது",
    "barrier": "பாதுகாப்பு செயல்படுகிறது",
    "settings": "அமைப்புகள்",
    "risk": "ஆபத்து மதிப்பெண்",
    "why": "ஏன் தடுக்கப்பட்டது",
    "network": "பிணைய பாதுகாப்பு",
    "apk": "APK ஸ்கேனர்",
    "history": "அச்சுறுத்தல் வரலாறு",
  },
  "hi": {
    "scan": "लिंक स्कैन करें",
    "protected": "सुरक्षित",
    "barrier": "सुरक्षा सक्रिय",
    "settings": "सेटिंग्स",
    "risk": "जोखिम स्कोर",
    "why": "क्यों रोका गया",
    "network": "नेटवर्क सुरक्षा",
    "apk": "APK स्कैनर",
    "history": "खतरे का इतिहास",
  }
};

void main() {
  runApp(const PhishieldApp());
}

/* ================= APP ================= */

class PhishieldApp extends StatelessWidget {
  const PhishieldApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: "Phishield",
      theme: ThemeData(
        useMaterial3: true,
        scaffoldBackgroundColor: const Color(0xFFF6F8FC),
        colorSchemeSeed: Colors.blue,
      ),
      home: const HomeScreen(),
    );
  }
}

/* ================= HOME ================= */

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});
  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;

  @override
  void initState() {
    super.initState();
    _controller =
        AnimationController(vsync: this, duration: const Duration(seconds: 2))
          ..repeat(reverse: true);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final t = uiLang[AppState.language]!;

    return Scaffold(
      appBar: AppBar(
        title: const Text("Phishield"),
        centerTitle: true,
        actions: [
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () async {
              await Navigator.push(
                context,
                MaterialPageRoute(builder: (_) => const SettingsScreen()),
              );
              setState(() {});
            },
          )
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          ScaleTransition(
            scale: Tween(begin: 0.95, end: 1.05).animate(_controller),
            child: _card(
              Column(
                children: [
                  Icon(Icons.shield,
                      size: 90,
                      color:
                          AppState.barrierOn ? Colors.red : Colors.green),
                  const SizedBox(height: 10),
                  Text(
                    AppState.barrierOn
                        ? t["barrier"]!
                        : t["protected"]!,
                    style: TextStyle(
                        fontSize: 22,
                        fontWeight: FontWeight.bold,
                        color: AppState.barrierOn
                            ? Colors.red
                            : Colors.green),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 20),

          _nav(context, Icons.link, t["scan"]!, () async {
            await Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const LinkScanScreen()),
            );
            setState(() {});
          }),

          _nav(context, Icons.android, t["apk"]!, () {
            Navigator.push(context,
                MaterialPageRoute(builder: (_) => const ApkScanScreen()));
          }),

          _nav(context, Icons.history, t["history"]!, () {
            Navigator.push(context,
                MaterialPageRoute(builder: (_) => const HistoryScreen()));
          }),

          const SizedBox(height: 20),
          _networkControls(),
        ],
      ),
    );
  }

  Widget _nav(
      BuildContext ctx, IconData icon, String text, VoidCallback onTap) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: InkWell(
        onTap: onTap,
        child: _card(
          Row(
            children: [
              Icon(icon, size: 30),
              const SizedBox(width: 16),
              Text(text,
                  style: const TextStyle(
                      fontSize: 18, fontWeight: FontWeight.w600)),
              const Spacer(),
              const Icon(Icons.arrow_forward_ios, size: 16),
            ],
          ),
        ),
      ),
    );
  }

  Widget _card(Widget child) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(20),
        boxShadow: const [
          BoxShadow(color: Colors.black12, blurRadius: 10)
        ],
      ),
      child: child,
    );
  }

  Widget _networkControls() {
    final t = uiLang[AppState.language]!;
    return _card(
      Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(t["network"]!,
              style:
                  const TextStyle(fontWeight: FontWeight.bold)),
          SwitchListTile(
            title: const Text("Wi-Fi Protection"),
            value: NetworkState.wifiProtection,
            onChanged: (v) =>
                setState(() => NetworkState.wifiProtection = v),
          ),
          SwitchListTile(
            title: const Text("VPN Detection"),
            value: NetworkState.vpnDetection,
            onChanged: (v) =>
                setState(() => NetworkState.vpnDetection = v),
          ),
          SwitchListTile(
            title: const Text("DNS Protection"),
            value: NetworkState.dnsProtection,
            onChanged: (v) =>
                setState(() => NetworkState.dnsProtection = v),
          ),
        ],
      ),
    );
  }
}

/* ================= LINK SCAN ================= */

class LinkScanScreen extends StatefulWidget {
  const LinkScanScreen({super.key});
  @override
  State<LinkScanScreen> createState() => _LinkScanScreenState();
}

class _LinkScanScreenState extends State<LinkScanScreen> {
  final TextEditingController controller = TextEditingController();
  bool loading = false;

  String verdict = "";
  int riskScore = 0;
  List<String> reasons = [];
  String backendMessage = "";
  Color verdictColor = Colors.grey;

  Color _color(String v) {
    if (v == "dangerous") return Colors.red;
    if (v == "suspicious") return Colors.orange;
    return Colors.green;
  }

  Future<void> scan() async {
  setState(() {
    loading = true;
    verdict = "";
  });

  final url = controller.text.toLowerCase();

  // 🔹 Mock phishing keywords (fallback logic)
  final riskyKeywords = [
    'login',
    'verify',
    'free',
    'offer',
    'bit.ly',
    'secure',
    'update',
    'bank',
    'account'
  ];

  bool isPhishing =
      riskyKeywords.any((word) => url.contains(word));

  await Future.delayed(const Duration(seconds: 1)); // fake scan delay

  if (isPhishing) {
    verdict = "dangerous";
    riskScore = 85;
    reasons = [
      "Suspicious keyword detected in URL",
      "Common phishing pattern found"
    ];
    backendMessage =
        "This link matches known phishing patterns.";
  } else {
    verdict = "safe";
    riskScore = 10;
    reasons = [];
    backendMessage = "No threats detected.";
  }

  verdictColor = _color(verdict);
  AppState.barrierOn = verdict != "safe";

  setState(() => loading = false);
}

  @override
  Widget build(BuildContext context) {
    final t = uiLang[AppState.language]!;
    return Scaffold(
      appBar: AppBar(title: Text(t["scan"]!)),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          TextField(
            controller: controller,
            decoration: InputDecoration(
              labelText: "URL",
              border:
                  OutlineInputBorder(borderRadius: BorderRadius.circular(16)),
            ),
          ),
          const SizedBox(height: 16),
          ElevatedButton(
            onPressed: loading ? null : scan,
            child: loading
                ? const CircularProgressIndicator()
                : Text(t["scan"]!),
          ),
          const SizedBox(height: 20),
          if (verdict.isNotEmpty)
            Container(
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: verdictColor.withOpacity(0.1),
                borderRadius: BorderRadius.circular(20),
              ),
              child: Column(
                children: [
                  Text(verdict.toUpperCase(),
                      style: TextStyle(
                          fontSize: 20,
                          fontWeight: FontWeight.bold,
                          color: verdictColor)),
                  const SizedBox(height: 10),
                  LinearProgressIndicator(
                      value: riskScore / 100,
                      color: verdictColor),
                  const SizedBox(height: 6),
                  Text("${t["risk"]!}: $riskScore%"),
                  const SizedBox(height: 10),
                  Text(backendMessage,
                      style: TextStyle(color: verdictColor)),
                  if (reasons.isNotEmpty) ...[
                    const SizedBox(height: 12),
                    Text(t["why"]!,
                        style: const TextStyle(
                            fontWeight: FontWeight.bold)),
                    ...reasons.map((r) => Text("• $r")),
                  ]
                ],
              ),
            ),
        ],
      ),
    );
  }
}

/* ================= OTHER SCREENS ================= */

class ApkScanScreen extends StatelessWidget {
  const ApkScanScreen({super.key});
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text("APK Scanner")),
      body: const Center(child: Text("APK scan backend ready")),
    );
  }
}

class HistoryScreen extends StatelessWidget {
  const HistoryScreen({super.key});
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text("Threat History")),
      body: const Center(child: Text("Threat history will appear here")),
    );
  }
}

/* ================= SETTINGS ================= */

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});
  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  @override
  Widget build(BuildContext context) {
    final t = uiLang[AppState.language]!;
    return Scaffold(
      appBar: AppBar(title: Text(t["settings"]!)),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          SwitchListTile(
            title: const Text("Real-time Protection"),
            value: SettingsState.realtimeProtection,
            onChanged: (v) =>
                setState(() => SettingsState.realtimeProtection = v),
          ),
          SwitchListTile(
            title: const Text("Safe Browsing Mode"),
            value: SettingsState.safeBrowsing,
            onChanged: (v) =>
                setState(() => SettingsState.safeBrowsing = v),
          ),
          SwitchListTile(
            title: const Text("Voice Alerts"),
            value: SettingsState.voiceAlerts,
            onChanged: (v) =>
                setState(() => SettingsState.voiceAlerts = v),
          ),
          const SizedBox(height: 20),
          RadioListTile(
            title: const Text("English"),
            value: "en",
            groupValue: AppState.language,
            onChanged: (v) =>
                setState(() => AppState.language = v.toString()),
          ),
          RadioListTile(
            title: const Text("தமிழ்"),
            value: "ta",
            groupValue: AppState.language,
            onChanged: (v) =>
                setState(() => AppState.language = v.toString()),
          ),
          RadioListTile(
            title: const Text("हिन्दी"),
            value: "hi",
            groupValue: AppState.language,
            onChanged: (v) =>
                setState(() => AppState.language = v.toString()),
          ),
        ],
      ),
    );
  }
}
