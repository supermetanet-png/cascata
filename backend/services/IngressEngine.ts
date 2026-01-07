
import { Pool, PoolClient } from 'pg';

export interface IngressContext {
    body: any;
    headers: any;
    query: any;
    timestamp: string;
}

export interface IngressStep {
    id: string;
    type: 'condition' | 'action_db' | 'action_rpc';
    config: any;
    // Condition Specific
    field?: string;
    operator?: 'eq' | 'neq' | 'gt' | 'lt' | 'contains';
    value?: any;
    true_steps?: IngressStep[];
    // Action Specific
    table?: string;
    operation?: 'INSERT' | 'UPDATE' | 'DELETE';
    data?: Record<string, any>; // Mapeamento Coluna -> Valor/Template
    match_field?: string; // Para UPDATE/DELETE
    match_value?: string; // Para UPDATE/DELETE
    rpc_name?: string;
    rpc_args?: Record<string, any>;
}

export class IngressEngine {

    /**
     * Resolve variáveis dinâmicas do contexto.
     * Suporta notação de ponto profunda: {{body.data.customer.id}}
     * Preserva tipos (não converte objeto para string se for a única variável).
     */
    private static resolveValue(template: any, context: IngressContext): any {
        if (typeof template !== 'string') return template;
        
        // Caso 1: Acesso direto a uma variável (ex: "{{body.data}}")
        // Retorna o valor original (objeto, array, numero) sem stringify.
        if (template.startsWith('{{') && template.endsWith('}}') && (template.match(/{{/g) || []).length === 1) {
            const path = template.slice(2, -2).trim();
            return this.getValueByPath(context, path);
        }

        // Caso 2: Interpolação de string (ex: "Order ID: {{body.id}}")
        // Converte tudo para string.
        return template.replace(/{{(.*?)}}/g, (_, path) => {
            const val = this.getValueByPath(context, path.trim());
            if (typeof val === 'object') return JSON.stringify(val);
            return val !== undefined && val !== null ? String(val) : '';
        });
    }

    private static getValueByPath(obj: any, path: string): any {
        return path.split('.').reduce((acc, part) => {
            if (acc === null || acc === undefined) return undefined;
            // Handle array access body.items[0]
            if (part.includes('[') && part.endsWith(']')) {
                const [name, indexStr] = part.split('[');
                const index = parseInt(indexStr.replace(']', ''));
                const arr = acc[name];
                return Array.isArray(arr) ? arr[index] : undefined;
            }
            return acc[part];
        }, obj);
    }

    /**
     * Executa o fluxo de regras
     */
    public static async executeFlow(steps: IngressStep[], context: IngressContext, client: PoolClient) {
        for (const step of steps) {
            await this.processStep(step, context, client);
        }
    }

    private static async processStep(step: IngressStep, context: IngressContext, client: PoolClient) {
        try {
            if (step.type === 'condition') {
                const actualValue = this.resolveValue(step.field, context);
                const expectedValue = this.resolveValue(step.value, context); 
                let pass = false;

                // Robust Comparison
                switch (step.operator) {
                    case 'eq': pass = actualValue == expectedValue; break; // Loose eq for "1" == 1
                    case 'neq': pass = actualValue != expectedValue; break;
                    case 'gt': pass = Number(actualValue) > Number(expectedValue); break;
                    case 'lt': pass = Number(actualValue) < Number(expectedValue); break;
                    case 'contains': 
                        if (Array.isArray(actualValue)) pass = actualValue.includes(expectedValue);
                        else if (typeof actualValue === 'string') pass = actualValue.includes(String(expectedValue));
                        else if (typeof actualValue === 'object') pass = JSON.stringify(actualValue).includes(String(expectedValue));
                        break;
                }

                if (pass && step.true_steps) {
                    await this.executeFlow(step.true_steps, context, client);
                }
                return;
            }

            if (step.type === 'action_db') {
                const { table, operation, data, match_field, match_value } = step.config;
                
                if (!table) throw new Error("Table name missing in action");

                if (operation === 'INSERT') {
                    const columns = Object.keys(data || {});
                    const values = columns.map(col => this.resolveValue(data[col], context));
                    const placeholders = values.map((_, i) => `$${i + 1}`).join(', ');
                    const colNames = columns.map(c => `"${c}"`).join(', ');

                    const sql = `INSERT INTO public."${table}" (${colNames}) VALUES (${placeholders})`;
                    await client.query(sql, values);
                } 
                else if (operation === 'UPDATE') {
                    const resolvedMatch = this.resolveValue(match_value, context);
                    const updateCols = Object.keys(data || {});
                    if (updateCols.length === 0) return;

                    const setClause = updateCols.map((col, i) => `"${col}" = $${i + 2}`).join(', ');
                    const values = updateCols.map(col => this.resolveValue(data[col], context));
                    
                    const sql = `UPDATE public."${table}" SET ${setClause} WHERE "${match_field}" = $1`;
                    await client.query(sql, [resolvedMatch, ...values]);
                }
                else if (operation === 'DELETE') {
                    const resolvedMatch = this.resolveValue(match_value, context);
                    const sql = `DELETE FROM public."${table}" WHERE "${match_field}" = $1`;
                    await client.query(sql, [resolvedMatch]);
                }
            }

            if (step.type === 'action_rpc') {
                const { rpc_name, rpc_args } = step.config;
                if (!rpc_name) return;

                const args = rpc_args || {};
                const keys = Object.keys(args);
                const values = keys.map(k => this.resolveValue(args[k], context));
                const placeholders = keys.map((_, i) => `$${i + 1}`).join(', ');

                const sql = `SELECT * FROM public."${rpc_name}"(${placeholders})`;
                await client.query(sql, values);
            }

        } catch (e: any) {
            console.error(`[IngressEngine] Step ${step.id} (${step.type}) Failed:`, e.message);
            // Re-throw to trigger rollback in the service layer
            throw new Error(`Flow Execution Error in step ${step.id}: ${e.message}`);
        }
    }
}
