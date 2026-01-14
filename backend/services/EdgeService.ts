import ivm from 'isolated-vm';
import { Pool } from 'pg';
import crypto from 'crypto';
import { Buffer } from 'buffer';
import axios from 'axios';
import { validateTargetUrl } from '../src/utils/index.js';

export class EdgeService {
    
    public static async execute(
        code: string,
        context: any,
        envVars: Record<string, string>,
        projectPool: Pool,
        timeoutMs: number = 5000,
        projectSlug: string // Added projectSlug for vector targeting
    ): Promise<{ status: number, body: any }> {
        
        const isolate = new ivm.Isolate({ memoryLimit: 256 });
        const scriptContext = await isolate.createContext();
        const jail = scriptContext.global;
        const qdrantUrl = `http://${process.env.QDRANT_HOST || 'qdrant'}:${process.env.QDRANT_PORT || '6333'}`;

        try {
            await jail.set('global', jail.derefInto());
            
            await jail.set('console', new ivm.Reference({
                log: new ivm.Callback((...args: any[]) => console.log(`[EDGE:${projectSlug}]`, ...args)),
                error: new ivm.Callback((...args: any[]) => console.error(`[EDGE:${projectSlug}]`, ...args)),
                warn: new ivm.Callback((...args: any[]) => console.warn(`[EDGE:${projectSlug}]`, ...args))
            }));

            await jail.set('env', new ivm.ExternalCopy(envVars).copyInto());
            await jail.set('req', new ivm.ExternalCopy(context).copyInto());

            await jail.set('_crypto_proxy', new ivm.Reference({
                randomUUID: () => crypto.randomUUID(),
                randomBytes: (size: number) => {
                    const buf = crypto.randomBytes(size);
                    return new ivm.ExternalCopy(buf.toString('hex')).copyInto();
                }
            }));

            await jail.set('_encoding_proxy', new ivm.Reference({
                btoa: (str: string) => Buffer.from(str).toString('base64'),
                atob: (str: string) => Buffer.from(str, 'base64').toString('binary')
            }));

            // --- DATABASE BRIDGE ---
            await jail.set('db', new ivm.Reference({
                query: new ivm.Reference(async (sql: string, params: any[]) => {
                    const client = await projectPool.connect();
                    try {
                        const result = await client.query(sql, params);
                        return new ivm.ExternalCopy(JSON.parse(JSON.stringify(result.rows))).copyInto();
                    } finally {
                        client.release();
                    }
                })
            }));

            // --- ZERO-TRUST VECTOR BRIDGE ---
            // Allows Edge Functions to query vectors without knowing internal network details
            await jail.set('_vector_proxy', new ivm.Reference({
                call: new ivm.Reference(async (method: string, subPath: string, data: any) => {
                    const target = `${qdrantUrl}/collections/${projectSlug}${subPath ? '/' + subPath : ''}`;
                    try {
                        const res = await axios({
                            method: method as any,
                            url: target,
                            data: data,
                            headers: { 'Content-Type': 'application/json' }
                        });
                        return new ivm.ExternalCopy(res.data).copyInto();
                    } catch (e: any) {
                        throw new Error(`Vector Engine Error: ${e.response?.data?.status?.error || e.message}`);
                    }
                })
            }));

            await jail.set('fetch', new ivm.Reference(async (url: string, initStr: any) => {
                let init = {};
                try { init = initStr ? JSON.parse(initStr) : {}; } catch(e) {}
                const controller = new AbortController();
                const id = setTimeout(() => controller.abort(), timeoutMs - 500);

                try {
                    await validateTargetUrl(url);
                    const response = await fetch(url, { ...init, signal: controller.signal });
                    clearTimeout(id);
                    const text = await response.text();
                    const headers: Record<string, string> = {};
                    response.headers.forEach((v, k) => headers[k] = v);
                    return new ivm.ExternalCopy({ status: response.status, statusText: response.statusText, headers, text }).copyInto();
                } catch (e: any) {
                    clearTimeout(id);
                    throw new Error(`Fetch Error: ${e.message}`);
                }
            }));

            const wrappedCode = `
                (async () => {
                    const crypto = {
                        randomUUID: () => _crypto_proxy.applySync(undefined, [], { result: { copy: true } }),
                        randomHex: (size) => _crypto_proxy.applySync(undefined, ['randomBytes', size], { result: { copy: true } })
                    };
                    global.crypto = crypto;
                    global.btoa = (s) => _encoding_proxy.applySync(undefined, ['btoa', s], { result: { copy: true } });
                    global.atob = (s) => _encoding_proxy.applySync(undefined, ['atob', s], { result: { copy: true } });

                    const $db = {
                        query: async (sql, params) => db.get('query').apply(undefined, [sql, params || []], { arguments: { copy: true }, result: { promise: true } })
                    };
                    
                    const $vector = {
                        search: (vector, params) => _vector_proxy.get('call').apply(undefined, ['POST', 'points/search', { vector, ...params }], { arguments: { copy: true }, result: { promise: true } }),
                        upsert: (points) => _vector_proxy.get('call').apply(undefined, ['PUT', 'points', { points }], { arguments: { copy: true }, result: { promise: true } }),
                        delete: (ids) => _vector_proxy.get('call').apply(undefined, ['POST', 'points/delete', { points: ids }], { arguments: { copy: true }, result: { promise: true } }),
                        info: () => _vector_proxy.get('call').apply(undefined, ['GET', '', {}], { arguments: { copy: true }, result: { promise: true } })
                    };

                    const $fetch = async (url, init) => {
                        const initStr = init ? JSON.stringify(init) : undefined;
                        const res = await fetch.apply(undefined, [url, initStr], { arguments: { copy: true }, result: { promise: true } });
                        return {
                            status: res.status,
                            headers: res.headers,
                            text: async () => res.text,
                            json: async () => JSON.parse(res.text)
                        };
                    };

                    const module = { exports: {} };
                    const exports = module.exports;
                    try {
                        ${code}
                        const result = (module.exports && typeof module.exports.default === 'function') 
                            ? await module.exports.default(req) 
                            : module.exports;
                        return JSON.stringify(result === undefined ? null : result);
                    } catch (e) {
                        return JSON.stringify({ error: e.message, stack: e.stack, isError: true });
                    }
                })()
            `;

            const script = await isolate.compileScript(wrappedCode);
            const resultStr = await script.run(scriptContext, { timeout: timeoutMs, promise: true });

            let result;
            try { result = JSON.parse(resultStr); } catch (e) { result = resultStr; }
            if (result && result.isError) return { status: 500, body: { error: result.error, stack: result.stack } };
            return { status: 200, body: result };
        } catch (e: any) {
            console.error("Edge Execution Error:", e.message);
            if (e.message.includes('isolate is disposed')) return { status: 504, body: { error: `Timed Out` } };
            return { status: 500, body: { error: `Runtime Error: ${e.message}` } };
        } finally {
            try { scriptContext.release(); if (!isolate.isDisposed) isolate.dispose(); } catch(cleanupErr) {}
        }
    }
}
