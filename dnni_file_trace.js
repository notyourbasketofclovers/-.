'use strict';

console.log('[DNNI TRACE] Starting...');

const handles = new Map();

function getExport(name) {
    try {
        return Module.getGlobalExportByName(name);
    } catch (e) {
        console.log(`[WARN] ${name}: ${e}`);
        return null;
    }
}

function readW(ptr) {
    try {
        if (ptr.isNull()) return null;
        return ptr.readUtf16String();
    } catch (_) {
        return null;
    }
}

function readA(ptr) {
    try {
        if (ptr.isNull()) return null;
        return ptr.readAnsiString();
    } catch (_) {
        return null;
    }
}

function interesting(path) {
    if (!path) return false;

    const p = path.toLowerCase();

    return p.includes('.dnni') ||
           p.includes('.dnnf');
}

function hookCreateFile(name, reader) {
    const addr = getExport(name);

    if (addr === null) {
        console.log(`[WARN] ${name} unavailable`);
        return;
    }

    console.log(`[HOOKED] ${name} @ ${addr}`);

    Interceptor.attach(addr, {
        onEnter(args) {
            this.path = reader(args[0]);
            this.log = interesting(this.path);
        },

        onLeave(retval) {
            if (!this.log)
                return;

            const invalid = ptr('0xffffffffffffffff');
            const success = !retval.equals(invalid);

            console.log(
                `[${name}] ` +
                `${this.path} ` +
                `handle=${retval} ` +
                `success=${success}`
            );

            if (success) {
                handles.set(retval.toString(), this.path);
            }
        }
    });
}

function hookCloseHandle() {
    const addr = getExport('CloseHandle');

    if (addr === null) {
        console.log('[WARN] CloseHandle unavailable');
        return;
    }

    console.log(`[HOOKED] CloseHandle @ ${addr}`);

    Interceptor.attach(addr, {
        onEnter(args) {
            const key = args[0].toString();

            if (handles.has(key)) {
                console.log(
                    `[CloseHandle] ${handles.get(key)}`
                );

                handles.delete(key);
            }
        }
    });
}

hookCreateFile('CreateFileW', readW);
hookCreateFile('CreateFileA', readA);
hookCloseHandle();

console.log('[DNNI TRACE] Ready.');