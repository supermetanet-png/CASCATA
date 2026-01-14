import { GoogleGenAI } from "@google/genai";
import { Pool } from 'pg';

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

export class AiService {
    
    private static getClient() {
        return new GoogleGenAI({ apiKey: process.env.API_KEY || '' });
    }

    private static async getContext(pool: Pool) {
        try {
            const tablesRes = await pool.query(`
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
                AND table_name NOT LIKE '_deleted_%'
            `);
            const tables = tablesRes.rows.map(r => r.table_name);
            
            let schemaSummary = "Database Schema Context:\n";
            for (const t of tables) {
                const cols = await pool.query(`
                    SELECT column_name, data_type, is_nullable 
                    FROM information_schema.columns 
                    WHERE table_name = $1 AND table_schema = 'public'
                `, [t]);
                schemaSummary += `- Table "${t}": ${cols.rows.map(c => `${c.column_name}(${c.data_type})`).join(', ')}\n`;
            }
            return schemaSummary;
        } catch (e) {
            console.error("[AiService] Context Extraction Error:", e);
            return "No schema context available due to internal database error.";
        }
    }

    private static async generateWithRetry(parameters: { model: string, contents: any, config?: any }, retries = 3, delay = 1000): Promise<string> {
        const ai = this.getClient();
        try {
            const response = await ai.models.generateContent(parameters);
            return response.text || '';
        } catch (error: any) {
            const status = error.status || error.response?.status;
            // Retry on 503 Service Unavailable, 429 Too Many Requests or Model Overloaded
            if ((status === 503 || status === 429 || error.message?.includes('overloaded')) && retries > 0) {
                console.warn(`[AiService] AI Overloaded (${status}). Retrying in ${delay}ms... (${retries} left)`);
                await sleep(delay);
                return this.generateWithRetry(parameters, retries - 1, delay * 2);
            }
            throw error;
        }
    }

    public static async chat(projectSlug: string, pool: Pool, systemSettings: any, body: any) {
        const { messages, config } = body;
        const modelName = 'gemini-3-flash-preview';
        
        let context = '';
        if (!config?.skip_db_context) {
            context = await this.getContext(pool);
        }

        const systemInstruction = `
            You are Cascata Architect, a world-class senior solo leveling backend engineer.
            You are managing a multi-tenant BaaS project named "${projectSlug}".
            
            Current ${context}
            
            Strict Operational Rules:
            1. For table creation, return a JSON block (wrapped in \`\`\`json):
            {
                "action": "create_table",
                "name": "table_name",
                "description": "brief purpose",
                "columns": [
                    {"name": "col", "type": "text|integer|boolean|uuid|timestamptz|jsonb", "isPrimaryKey": true/false, "description": "desc"}
                ]
            }
            2. For SQL queries, wrap them in \`\`\`sql.
            3. Be precise, technical, and prioritize PostgreSQL best practices.
        `;

        const lastMsg = messages[messages.length - 1].content;
        
        const text = await this.generateWithRetry({
            model: modelName,
            contents: [
                { role: 'user', parts: [{ text: `Conversation History: ${JSON.stringify(messages.slice(0, -1))}\n\nLatest Request: ${lastMsg}` }] }
            ],
            config: { 
                systemInstruction, 
                temperature: 0.2,
                topK: 40,
                topP: 0.95
            }
        });

        return { choices: [{ message: { role: 'assistant', content: text } }] };
    }

    public static async draftDoc(projectSlug: string, pool: Pool, systemSettings: any, tableName: string) {
        const modelName = 'gemini-3-flash-preview';
        const cols = await pool.query(`
            SELECT column_name, data_type, is_nullable 
            FROM information_schema.columns 
            WHERE table_name = $1 AND table_schema = 'public'
        `, [tableName]);
        
        const schemaStr = cols.rows.map(c => `- ${c.column_name} (${c.data_type}) ${c.is_nullable === 'YES' ? '(Optional)' : '(Required)'}`).join('\n');

        const prompt = `Act as a Technical Writer. Write a clear API integration guide for project "${projectSlug}" and table "${tableName}". 
        
        Schema Information:
        ${schemaStr}
        
        Use Markdown. Include code examples using 'curl'. Focus on production robustness.`;
        
        const text = await this.generateWithRetry({ model: modelName, contents: prompt });

        return { 
            id: `doc-${tableName}-${Date.now()}`, 
            title: `Integration Guide: ${tableName}`, 
            content_markdown: text 
        };
    }

    public static async fixSQL(projectSlug: string, pool: Pool, systemSettings: any, sql: string, error: string) {
        const modelName = 'gemini-3-pro-preview';
        const context = await this.getContext(pool);
        
        const prompt = `Context: Cascata BaaS Project "${projectSlug}".
        Database Schema:
        ${context}
        
        The following SQL failed:
        \`\`\`sql
        ${sql}
        \`\`\`
        
        Error Message: "${error}"
        
        Task: Analyze the error and return the CORRECTED SQL inside a \`\`\`sql block. Explain briefly the fix.`;

        const text = await this.generateWithRetry({ model: modelName, contents: prompt });
        
        const match = text.match(/```sql\n([\s\S]*?)\n```/) || text.match(/```\n([\s\S]*?)\n```/);
        return match ? match[1].trim() : text.trim();
    }

    public static async explainCode(projectSlug: string, pool: Pool, systemSettings: any, code: string, type: 'sql' | 'js') {
        const modelName = 'gemini-3-pro-preview';
        const prompt = `You are a Senior Engineer. Explain the following ${type.toUpperCase()} code implemented for project "${projectSlug}".
        Highlight security implications and performance considerations.
        
        Code:
        \`\`\`${type}
        ${code}
        \`\`\``;
        
        const text = await this.generateWithRetry({ model: modelName, contents: prompt });
        return { explanation: text };
    }
}