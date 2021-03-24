/*
 * IOTracy.js
 * To run this script: frida -U bluetoothd --no-pause -I iotracy.js
 * - Trace libdipatch calls (credit: Jiska)
 * - Trace calls to iokit IOConnectCallMethod, IOConnectCallAsyncMethod, IOConnectCallAsyncScalarMethod, IOConnectCallAsyncStructMethod
 * - Trace calls to iokit IOServiceOpen ? (credit: mwr labs)
 * ----
 *  TODO:
 *  Trace IOConnectCallStructMethod and IOConnectCallScalarMethod explicitly
 *  Option to write call args to file
*/

// Settings
var BACKTRACE_LIBDISPATCH = false;
var BACKTRACE_IOCONNECTCALL = true;
var HEXDUMP_IOCONNECTCALL_POINTERS = true;


// Helper Functions
// 
function log_function_call(fname, args, argc){
    var s = fname + "(";
    for (var i = 0; i< argc; i++){
        s += args[i];
        if(i != argc - 1){
            s += ", ";
        }
    }
    s += ");";
    console.log(s);
}
//
var _ioobjectgetclass_addr = Module.findExportByName(null, 'IOObjectGetClass');
var _IOObjectGetClass = new NativeFunction(this._ioobjectgetclass_addr, "int", ["pointer", "pointer"]);
var service_ids = new Array();


// IOServiceOpen
var _ioserviceopen_addr = Module.getExportByName('IOKit', 'IOServiceOpen');
Interceptor.attach(_ioserviceopen_addr, {
    onEnter: function(args) {
        console.log("IOServiceOpen called");
        this.connection_ptr = args[3];
        this.classname = Memory.alloc(256);
        _IOObjectGetClass(args[0], this.classname);
        console.log("    IOObjectGetClass = " + Memory.readUtf8String(this.classname));
        this.type = args[2];
        log_function_call("IOServiceOpen", args, 4);

    },
    onLeave: function(retval) {
        if(retval == 0){
            var handle = Memory.readU32(this.connection_ptr);
            var userclient = Memory.readUtf8String(this.classname);
            console.log("IOServiceOpen ret = " + handle);
            console.log("IOServiceOpen UserClient = " + userclient);
            console.log("IOServiceOpen type = " + this.type);
            service_ids[handle] = [userclient, this.type];
        }
    }
});


// IOConnectCallMethod
var _ioconnectcallmethod_addr = Module.getExportByName('IOKit', 'IOConnectCallMethod');

Interceptor.attach(_ioconnectcallmethod_addr, {
    onEnter: function(args){
        var connection = args[0].toInt32();
        var selector = args[1].toInt32();
        var input_scalar = args[2];
        var input_scalar_count = args[3].toInt32();
        var input_struct = args[4];
        var input_struct_count = args[5].toInt32();
        var output_scalar = args[6];
        var output_scalar_count = 0;
        console.log("\nIOConnectCallMethod(" +  
            connection + ", " + 
            selector + ", " + 
            input_scalar_count + ", " + 
            input_struct_count + ", " + 
            output_scalar_count + ", " + 
            ");");
        try{
            console.log("    IOConnectCallMethod Service = " + service_ids[connection][0])
        } catch(e) {
            console.log("    IOConnectCallMethod Service = UNKNOWN ("  + connection + ")")
        }
        console.log("    IOConnectCallMethod Selector = " + selector)
        console.log("    IOConnectCallMethod ScalarInputCount = " + input_scalar_count)
        for(var i=0;i<input_scalar_count;i++){
            var val = input_scalar.add(0x8 * i).readPointer();
            console.log("        input[" + i + "] = " + val );
            try{
                if (HEXDUMP_IOCONNECTCALL_POINTERS)
                    console.log(hexdump(val, {
                      offset: 0,
                      length: 64,
                      header: true,
                      ansi: true
                    }));
            } catch(e){};
        }
        if(BACKTRACE_IOCONNECTCALL)
            console.log('        IOConnectCallMethod backtrace:\n        ' +
            Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join('\n        ') + '\n');

    },
    onLeave: function(retval){

    }
});

// IOConnectCallAsyncMethod
var _ioconnectcallasyncmethod_addr = Module.getExportByName('IOKit', 'IOConnectCallAsyncMethod');

Interceptor.attach(_ioconnectcallasyncmethod_addr, {
    onEnter: function(args){
        var connection = args[0].toInt32();
        var selector = args[1].toInt32();
        var input_scalar = args[5];
        var input_scalar_count = args[6].toInt32();
        var input_struct = args[7];
        var input_struct_count = args[8].toInt32();
        var output_scalar = args[9];
        var output_scalar_count = 0;
        console.log("IOConnectCallAsyncMethod(" +  
            connection + ", " + 
            selector + ", " + 
            input_scalar_count + ", " + 
            input_struct_count + ", " + 
            output_scalar_count + ", " + 
            ");");
        console.log("IOConnectCallAsyncMethod Service = " + service_ids[connection][0])
    },
    onLeave: function(retval){

    }
});

// IOConnectCallAsyncScalarMethod
var _ioconnectcallasyncscalarmethod_addr = Module.getExportByName('IOKit', 'IOConnectCallAsyncScalarMethod');

Interceptor.attach(_ioconnectcallasyncscalarmethod_addr, {
    onEnter: function(args){
        var connection = args[0].toInt32();
        var selector = args[1].toInt32();
        var async_ref_callback_addr = args[3].add(0x8).readPointer();
        var callback_fn_name = DebugSymbol.fromAddress(async_ref_callback_addr);
        var input_scalar = args[5];
        var input_scalar_count = args[6].toInt32();
        var output_scalar = args[7];
        var output_scalar_count = 0;
        console.log("IOConnectCallAsyncScalarMethod(" +  
            connection + ", " + 
            selector + ", " + 
            input_scalar_count + ", " + 
            output_scalar_count + ", " + 
            ");");
        try{
            console.log("    IOConnectCallAsyncScalarMethod Service = " + service_ids[connection][0])
        } catch(e) {
            console.log("    IOConnectCallAsyncScalarMethod Service = UNKNOWN ("  + connection + ")")
        }
        console.log("    IOConnectCallAsyncScalarMethod Selector = " + selector)
        console.log("    IOConnectCallAsyncScalarMethod Callback = " + callback_fn_name)
        console.log("    IOConnectCallAsyncScalarMethod InputCount = " + input_scalar_count)
        for(var i=0;i<input_scalar_count;i++){
            var val = input_scalar.add(0x8 * i).readPointer();
            console.log("        input[" + i + "] = " + val );
            try{
                if (HEXDUMP_IOCONNECTCALL_POINTERS)
                    console.log(hexdump(val, {
                      offset: 0,
                      length: 64,
                      header: true,
                      ansi: true
                    }));
            } catch(e){};
        }
        if(BACKTRACE_IOCONNECTCALL)
            console.log('        IOConnectCallAsyncScalarMethod backtrace:\n        ' +
            Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join('\n        ') + '\n');
    },
    onLeave: function(retval){

    }
});

// IOConnectCallAsyncStructMethod
var _ioconnectcallasyncstructmethod_addr = Module.getExportByName('IOKit', 'IOConnectCallAsyncStructMethod');

Interceptor.attach(_ioconnectcallasyncstructmethod_addr, {
    onEnter: function(args){
        var connection = args[0].toInt32();
        var selector = args[1].toInt32();
        var async_ref_callback_addr = args[3].add(0x8).readPointer();
        var callback_fn_name = DebugSymbol.fromAddress(async_ref_callback_addr);
        var input_struct = args[5];
        var input_struct_count = args[6].toInt32();
        var output_scalar = args[7];
        var output_scalar_count = 0;
        console.log("IOConnectCallAsyncStructMethod(" +  
            connection + ", " + 
            selector + ", " + 
            input_struct_count + ", " + 
            output_scalar_count + ", " + 
            ");");
        console.log("    IOConnectCallAsyncStructMethod Service = " + service_ids[connection][0])
        console.log("    IOConnectCallAsyncStructMethod Callback = " + callback_fn_name)
    },
    onLeave: function(retval){

    }
});


// LibDispatch Stuff...

var _dispatch_async_addr = Module.getExportByName('libdispatch.dylib', 'dispatch_async');
var _dispatch_queue_get_label_addr = Module.getExportByName('libdispatch.dylib', 'dispatch_queue_get_label');
var _dispatch_queue_get_label = new NativeFunction(this._dispatch_queue_get_label_addr, "pointer", ["pointer"]);
Interceptor.attach(_dispatch_async_addr, {
    onEnter: function(dispatch_queue, block) {
    
    	var queue = this.context.x0;
    	// console.log('dispatch queue ptr: ' + queue);
    	var label = _dispatch_queue_get_label(queue);
    	console.log('\nCalling queue: ' + label.readUtf8String());
    	
    	//print the nsstackblock function we're going to call
    	//should be at offset 0x10 ... it's the actual address but only the least significant bytes are relevant
    	var dispatch_block = this.context.x1;
    	console.log('Callback function: ' + DebugSymbol.fromAddress(dispatch_block.add(0x10).readPointer()));
    	
        if (BACKTRACE_LIBDISPATCH)
            console.log('dispatch_async backtrace:\n' +
            Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join('\n') + '\n');
    },
});
