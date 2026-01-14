
import { Queue, Worker, Job } from 'bullmq';
import crypto from 'crypto';
import axios from 'axios';
import { URL } from 'url';
import dns from 'dns/promises';

const REDIS_CONFIG = {
    connection: {
        host: process.env.REDIS_HOST || 'redis',
        port: parseInt(process.env.REDIS_PORT || '6379')
    }
};

export class QueueService {
    private static webhookQueue: Queue;
    private static webhookWorker: Worker;

    // SSRF Protection (Security)
    private static isPrivateIP(ip: string): boolean {
        if (ip.includes('.')) {
            const parts = ip.split('.').map(Number);
            if (parts.length !== 4) return false; 
            if (parts[0] === 0) return true;
            if (parts[0] === 10) return true;
            if (parts[0] === 127) return true;
            if (parts[0] === 169 && parts[1] === 254) return true;
            if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
            if (parts[0] === 192 && parts[1] === 168) return true;
        } 
        else if (ip.includes(':')) {
            if (ip === '::1' || ip === '::') return true;
            if (ip.toLowerCase().startsWith('fc') || ip.toLowerCase().startsWith('fd')) return true;
            if (ip.toLowerCase().startsWith('fe80')) return true;
        }
        return false;
    }

    private static async validateTarget(targetUrl: string): Promise<void> {
        try {
            const url = new URL(targetUrl);
            const hostname = url.hostname;

            if (hostname === 'localhost' || hostname === '::1' || hostname === '0.0.0.0') {
                throw new Error("Blocked: localhost access denied");
            }
            
            const internalServices = ['redis', 'db', 'backend_control', 'backend_data', 'nginx', 'nginx_controller'];
            if (internalServices.includes(hostname)) {
                throw new Error("Blocked: Internal service access denied");
            }

            let ips: string[] = [];
            const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':');
            
            if (isIp) {
                ips = [hostname];
            } else {
                try {
                    const records = await dns.lookup(hostname, { all: true });
                    ips = records.map(r => r.address);
                } catch (e) {
                    throw new Error(`DNS Resolution failed for ${hostname}`);
                }
            }

            for (const ip of ips) {
                if (this.isPrivateIP(ip)) {
                    throw new Error(`Security Violation: Host ${hostname} resolves to private IP ${ip}. Webhook blocked.`);
                }
            }

        } catch (e: any) {
            throw new Error(`SSRF Protection: ${e.message}`);
        }
    }

    public static init() {
        console.log('[QueueService] Initializing BullMQ Queues...');

        // 1. Fila Principal
        this.webhookQueue = new Queue('cascata-webhooks', {
            ...REDIS_CONFIG,
            defaultJobOptions: {
                removeOnComplete: { age: 3600 * 24, count: 1000 },
                removeOnFail: { age: 3600 * 24 * 7, count: 5000 }
            }
        });

        // 2. Worker Inteligente
        this.webhookWorker = new Worker('cascata-webhooks', async (job: Job) => {
            const { targetUrl, payload, secret, eventType, tableName, fallbackUrl } = job.data;
            
            // Re-validate URL on execution
            await this.validateTarget(targetUrl);

            const signature = crypto
                .createHmac('sha256', secret)
                .update(JSON.stringify(payload))
                .digest('hex');

            try {
                console.log(`[Queue:Webhook] Processing job ${job.id} -> ${targetUrl} (Attempt ${job.attemptsMade + 1}/${job.opts.attempts})`);
                
                await axios.post(targetUrl, payload, {
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Cascata-Signature': signature,
                        'X-Cascata-Event': eventType,
                        'X-Cascata-Table': tableName,
                        'User-Agent': 'Cascata-Webhook-Engine/2.2'
                    },
                    timeout: 10000 
                });
                
                return { status: 'sent', timestamp: new Date() };

            } catch (error: any) {
                const isLastAttempt = job.attemptsMade >= (job.opts.attempts || 1) - 1;
                const errorMsg = error.response ? `HTTP ${error.response.status}: ${JSON.stringify(error.response.data)}` : error.message;

                console.error(`[Queue:Webhook] Failed job ${job.id}: ${errorMsg}`);

                // --- FALLBACK TRIGGER LOGIC ---
                // Se for a última tentativa E houver URL de fallback configurada
                if (isLastAttempt && fallbackUrl) {
                    console.warn(`[Queue:Webhook] Triggering Fallback Alert for job ${job.id} -> ${fallbackUrl}`);
                    
                    const alertPayload = {
                        alert: "Webhook Delivery Failed (Final)",
                        original_target: targetUrl,
                        error: errorMsg,
                        event: eventType,
                        table: tableName,
                        failed_at: new Date().toISOString(),
                        original_payload: payload // Include original data so user can manually recover in n8n/Zapier
                    };

                    try {
                        // Validate Fallback URL first
                        await this.validateTarget(fallbackUrl);
                        
                        await axios.post(fallbackUrl, alertPayload, {
                            headers: { 'Content-Type': 'application/json', 'User-Agent': 'Cascata-Alert-System' },
                            timeout: 5000
                        });
                        console.log(`[Queue:Webhook] Fallback alert sent successfully.`);
                    } catch (fbError: any) {
                        console.error(`[Queue:Webhook] Fallback FAILED: ${fbError.message}`);
                    }
                }
                
                // Se a resposta for 4xx (Erro do Cliente), NÃO RETENTAR (a menos que seja 429)
                if (error.response && error.response.status >= 400 && error.response.status < 500 && error.response.status !== 429) {
                    // Mas ainda queremos que o Fallback dispare acima, então jogamos o erro aqui para marcar como failed
                    // Como não estamos usando UnrecoverableError, apenas deixamos falhar.
                }
                
                throw error; 
            }
        }, REDIS_CONFIG);

        this.webhookWorker.on('failed', (job, err) => {
            // Logs de falha definitiva
        });
    }

    public static async addWebhookJob(data: any) {
        if (!this.webhookQueue) {
            this.init();
        }

        // Apply Retry Policy per Job
        const policy = data.retryPolicy || 'standard';
        let attempts = 10;
        let backoff: any = { type: 'exponential', delay: 1000 };

        if (policy === 'none') {
            attempts = 1; // Critical / Payment mode
        } else if (policy === 'linear') {
            attempts = 5;
            backoff = { type: 'fixed', delay: 5000 }; // Retry every 5s
        }

        await this.webhookQueue.add('dispatch', data, {
            attempts,
            backoff
        });
    }

    public static async getMetrics() {
        if (!this.webhookQueue) return { waiting: 0, active: 0, failed: 0, completed: 0 };
        return await this.webhookQueue.getJobCounts('waiting', 'active', 'failed', 'completed');
    }
}
