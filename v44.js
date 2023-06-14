// V44.242 Script by Solar

const Libg = {
    init() {
        let module = Process.findModuleByName('libg.so');
        Libg.begin = module.base;
        Libg.size = module.size;
        Libg.end = Libg.begin.add(Libg.size);
    },
    offset(addr) {
        return Libg.begin.add(addr);
    }
}

const Armceptor = {
	nop: function(addr) {
		Memory.patchCode(addr, Process.pageSize, function(code) {
			var writer = new ArmWriter(code, {
				pc: addr
			});
			writer.putNop();
			writer.flush();
		});
	},
    ret: function(addr) {
		Memory.patchCode(addr, Process.pageSize, function(code) {
			var writer = new ArmWriter(code, {
				pc: addr
			});
			writer.putRet();
			writer.flush();
		});
	},
	jumpOffset: function(addr, target) {
		Memory.patchCode(addr, Process.pageSize, function(code) {
			var writer = new ArmWriter(code, {
				pc: addr
			});
			writer.putBImm(target);
			writer.flush();
		});
	},
	jumpout: function(addr, target) {
		Memory.patchCode(addr, Process.pageSize, function(code) {
			var writer = new ArmWriter(code, {
				pc: addr
			});
			writer.putBranchAddress(target);
			writer.flush();
		});
	}
}

const Connect = {
    init() {
        Interceptor.attach(Libg.offset(0x9ED4B0), { // ServerConnection::connectTo
            onEnter(args) {
                args[1].add(8).readPointer().writeUtf8String("192.168.0.102");
                SetupMessaging.init();
            }
        });
    }
}

const SetupMessaging = { // CryptoKill doesn't work
    init() {
        Armceptor.ret(Libg.offset(0x544728)); // Messaging::decryptData
        Interceptor.attach(Libg.offset(0xA1853C), { // Messaging::sendPepperAuthentication
            onEnter(args) {
                // ...
            },
            onLeave(retval) {
                // ...
            }
        });
        Interceptor.attach(Libg.offset(0x847370), function() { // Messaging::encryptAndWrite
            this.context.r0 = 0x2774; // 10100: ClientHelloMessage
        });
        SetupMessaging.ClientSecretKeyPatch(); // ClientSecretKeyPatch works
    },
    ClientSecretKeyPatch() {
        Interceptor.attach(Libg.offset(0xBA4D3C), { // randombytes in PepperEncrypter::PepperEncrypter
            onLeave(retval) {
                retval.writeByteArray([0xD7, 0xA8, 0x21, 0x75, 0x06, 0xB9, 0x82, 0x38, 0xEF, 0x32, 0xCD, 0xD2, 0x27, 0x2B, 0x9D, 0xEC, 0x20, 0xF1, 0xA1, 0x6D, 0x28, 0x3F, 0x55, 0xFD, 0x94, 0xA3, 0x75, 0xE3, 0x62, 0x79, 0x6E, 0x97]);
            }
        });
    }
}

const Hook = {
    init() {
        const ReceiveMessage = Interceptor.attach(Libg.offset(0x51C5E8), { // MessageManager::receiveMessage
            onEnter(args) {
                const Msg = args[1];
                const MsgType = new NativeFunction(Memory.readPointer(Memory.readPointer(Msg).add(20)), 'int', ['pointer'])(Msg);
                if (MsgType === 20104) { // LoginOkMessage
                    Misc();
                    ReceiveMessage.detach();
                }
            }
        });
    }
}

const Misc = {
    init() {
        Interceptor.replace(Libg.offset(0xC0FE5C), new NativeCallback(function() { // LogicVersion::isDevelopmentBuild
            return 1;
        }, 'int', []));

        Interceptor.replace(Libg.offset(0x802DF8), new NativeCallback(function() { // LogicVersion::isProd
            return 0;
        }, 'int', []));

        Interceptor.attach(Libg.offset(0x38A884), { // HomePage::startGame
	    	onEnter(args) {
	    		args[3] = ptr(3);
            }
        });

        const LatencyTestResultText = Libg.offset(0x1262BC1);

        Memory.protect(LatencyTestResultText, 53, 'rwx');
        LatencyTestResultText.writeUtf8String("\nV44.242.1 Script by Solar\nOffline Battles by Lwitchy");
    }
}

const ArxanKiller = {
    init() {
        Armceptor.jumpout(Libg.offset(0x88E230), Libg.offset(0x892070)); // g_createGameInstanceJump
        Armceptor.jumpout(Libg.offset(0x811D0C), Libg.offset(0x812960)); // UnknownProt_Jump
        Armceptor.jumpout(Libg.offset(0x4635AC), Libg.offset(0x4644E8)); // GameMain::initJump
        Armceptor.jumpout(Libg.offset(0x7DCB40), Libg.offset(0x7DDDE0)); // InputSystem::updateJump
        Armceptor.jumpout(Libg.offset(0x730DA4), Libg.offset(0x731CE8)); // ResourceManager::initJump
        Armceptor.jumpout(Libg.offset(0x54A9F0), Libg.offset(0x54BA08)); // LoginMessage::encodeJump
        Armceptor.jumpout(Libg.offset(0x1E4678), Libg.offset(0x1E5B0C)); // UnknownProt_Jump

        Interceptor.replace(Module.findExportByName('libc.so', 'openat'), new NativeCallback(function() { // OpenAtJump
            return -1;
        }, 'int', []));
        Interceptor.replace(Libg.offset(0x7FAF88), new NativeCallback(function() {}, 'void', ['int'])); // AntiCheat::guard_callbackJump
    }
}

rpc.exports.init = function() {
    Libg.init();
    ArxanKiller.init();
    Connect.init();
    Hook.init();
}