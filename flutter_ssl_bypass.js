var do_dlopen = null;
var call_constructor = null;
Process.findModuleByName("linker64").enumerateSymbols().forEach(function(symbol){
    if(symbol.name.indexOf("do_dlopen") >= 0){
        do_dlopen = symbol.address;
    }
    if(symbol.name.indexOf("call_constructor") >= 0){
        call_constructor = symbol.address;
    }
});

var lib_loaded = 0;
Interceptor.attach(do_dlopen,function(){
    var library_path = this.context.x0.readCString();
    if(library_path.indexOf("libflutter.so") >= 0){
        Interceptor.attach(call_constructor, function(){
            if(lib_loaded == 0){
                lib_loaded = 1;
                var module = Process.findModuleByName("libflutter.so");
                console.log(`[+] libflutter is loaded at ${module.base}`);
                session_verify_cert_chain(module.base.add(0x5dc730));
            }
            
            
        })
    }
});

function session_verify_cert_chain(address){
    Interceptor.attach(address, {
        onLeave: function(retval){
            retval.replace(0x1);
            console.log(`[+] session_verify_cert_chain retval: ${retval}`);
        }
    });
}