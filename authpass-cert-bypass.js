
const BURP_IP   = '192.168.1.4';   // <-- your Mac's LAN IP
const BURP_PORT = 8080;             // <-- Burp's listener port

// ---- 1) ROUTING: redirect the app's 80/443 connections to Burp ----
const connect = Module.getGlobalExportByName('connect');
Interceptor.attach(connect, {
  onEnter(args) {
    const sa = args[1];
    const family = sa.add(1).readU8();          // sin_family
    if (family !== 2) return;                    // AF_INET only (see IPv6 note)
    const port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();  // sin_port (network order)
    if (port !== 443 && port !== 80) return;

    // rewrite destination -> Burp
    const oct = BURP_IP.split('.').map(Number);
    sa.add(4).writeU8(oct[0]); sa.add(5).writeU8(oct[1]);
    sa.add(6).writeU8(oct[2]); sa.add(7).writeU8(oct[3]);        // sin_addr
    sa.add(2).writeU8((BURP_PORT >> 8) & 0xff);
    sa.add(3).writeU8(BURP_PORT & 0xff);                         // sin_port
    console.log('[>] redirected :' + port + ' -> ' + BURP_IP + ':' + BURP_PORT);
  }
});




const WRAPPER_OFFSET = 0x005db2ec;

function matches(m) {return m.path.endsWith('App.framework/App');}

function hookCert(app){
	Interceptor.attach(app.base.add(WRAPPER_OFFSET), {
		onEnter(){
			console.log(`[+] wrapper entered..`);
		},
		onLeave(retval){
			retval.replace(this.context.x22.add(0x20));
			console.log(`Forcefully returned true...`);
		}
	});
}

const existing = Process.enumerateModules().find(matches);

if(existing) hookCert(existing);
else{
	const obs = Process.attachModuleObserver({
		onAdded(m) {
			if(matches(m)) {
				hookCert(m);
				obs.detach();
			}
		}
	});
}
