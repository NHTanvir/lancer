//! Frida snippets for SSL-pinning bypass. Drop these via:
//!   frida -U -l snippet.js -f com.target.app --no-pause

pub const ANDROID_SSL_PIN_BYPASS: &str = r#"// Lancer — Android SSL pinning bypass (OkHttp + TrustManager + WebView)
Java.perform(function() {
  // OkHttp 3.x CertificatePinner
  try {
    var Pinner = Java.use('okhttp3.CertificatePinner');
    Pinner.check.overload('java.lang.String', 'java.util.List').implementation = function() { return; };
    Pinner.check.overload('java.lang.String', 'java.security.cert.Certificate[]').implementation = function() { return; };
  } catch (e) {}

  // X509TrustManager
  try {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustAll = Java.registerClass({
      name: 'lancer.TrustAll', implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function() {},
        checkServerTrusted: function() {},
        getAcceptedIssuers: function() { return []; }
      }
    });
    var init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
    init.implementation = function(km, tm, sr) {
      return init.call(this, km, [TrustAll.$new()], sr);
    };
  } catch (e) {}
});"#;

pub const IOS_SSL_PIN_BYPASS: &str = r#"// Lancer — iOS SSL pinning bypass (NSURLSession + AFNetworking + Alamofire)
var SSLPinning = ObjC.classes.NSURLSession['- delegate'];
Interceptor.attach(ObjC.classes.NSURLAuthenticationChallenge['- sender'].implementation, {
  onEnter(args) {}, onLeave(retval) {}
});

// AFNetworking
try {
  var policy = ObjC.classes.AFSecurityPolicy['+ policyWithPinningMode:'];
  Interceptor.attach(policy.implementation, {
    onLeave(retval) { new ObjC.Object(retval).setAllowInvalidCertificates_(true); }
  });
} catch (e) {}"#;

pub const FLUTTER_BYPASS: &str = r#"// Lancer — Flutter pinning bypass (BoringSSL ssl_verify_peer_cert)
// Run on a rooted device; finds the BoringSSL stub inside libflutter.so.
var libflutter = Module.findBaseAddress("libflutter.so");
if (libflutter !== null) {
  Memory.scan(libflutter, 0x10000000, "2D E9 F0 4F", {
    onMatch(addr) {
      Interceptor.attach(addr, { onLeave(retval) { retval.replace(0x1); } });
    },
    onComplete() {}
  });
}"#;
