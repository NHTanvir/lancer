//! iOS — emits step-by-step CA install instructions and a configuration
//! profile that can be airdropped to the device.

pub fn install_steps(ca_pem_url: &str) -> String {
    format!(r#"iOS CA install — three steps:

  1. Open Safari on the device and visit: {ca_pem_url}
     (or AirDrop the .mobileconfig to the device).
  2. Settings → Profile Downloaded → Install (enter passcode).
  3. Settings → General → About → Certificate Trust Settings →
     turn ON "Enable Full Trust For Root Certificate" → Continue.

  Then in Settings → Wi-Fi → (your network) → Configure Proxy → Manual,
  point to Lancer's listen address (typically `<host>:8080`).
"#)
}

/// Build a `.mobileconfig` XML for one-shot install of the supplied CA cert.
pub fn make_profile(ca_pem_b64: &str, name: &str, identifier: &str) -> String {
    format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key><array>
    <dict>
      <key>PayloadType</key><string>com.apple.security.root</string>
      <key>PayloadIdentifier</key><string>{identifier}.ca</string>
      <key>PayloadUUID</key><string>00000000-0000-0000-0000-000000000001</string>
      <key>PayloadDisplayName</key><string>{name} CA</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadContent</key>
      <data>
{ca_pem_b64}
      </data>
    </dict>
  </array>
  <key>PayloadDisplayName</key><string>{name} root CA</string>
  <key>PayloadIdentifier</key><string>{identifier}</string>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>00000000-0000-0000-0000-000000000000</string>
  <key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
"#)
}
