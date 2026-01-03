
import { PoolClient } from 'pg';

interface PostgrestQuery {
    text: string;
    values: any[];
    countQuery?: string; // Optional separate query for exact count
}

export class PostgrestService {

    /**
     * Main entry point to handle a PostgREST-style request.
     */
    public static buildQuery(
        tableName: string,
        method: string,
        query: any,
        body: any,
        headers: any
    ): PostgrestQuery {
        const safeTable = `"${tableName.replace(/"/g, '""')}"`;
        const params: any[] = [];
        let sql = '';
        let countQuery = '';

        // 1. Extract Reserved Params (Pagination, Select, Order)
        // Handle encoded * (%2A) which might come through depending on proxy setup
        let selectParam = query.select || '*';
        if (selectParam === '%2A') selectParam = '*';
        
        const orderParam = query.order;
        const limitParam = query.limit;
        const offsetParam = query.offset;
        const onConflictParam = query.on_conflict; // For UPSERT

        // 2. Build Filters (Everything else in query is a filter)
        const filters: string[] = [];
        Object.keys(query).forEach(key => {
            if (['select', 'order', 'limit', 'offset', 'on_conflict', 'columns'].includes(key)) return;
            
            const value = query[key];
            const { clause, val } = this.parseFilter(key, value, params.length + 1);
            if (clause) {
                filters.push(clause);
                if (val !== undefined) {
                    // Handle array inputs for IN operator
                    if (Array.isArray(val)) {
                        val.forEach(v => params.push(v));
                    } else {
                        params.push(val);
                    }
                }
            }
        });

        const whereClause = filters.length > 0 ? `WHERE ${filters.join(' AND ')}` : '';

        // 3. Handle Methods
        if (method === 'GET') {
            // SELECT
            const columns = this.parseSelect(selectParam);
            const orderBy = this.parseOrder(orderParam);
            
            // Pagination
            let limitClause = '';
            let offsetClause = '';

            // Handle Range Header (Range: bytes=0-9)
            if (headers['range']) {
                const rangeMatch = headers['range'].match(/(\d+)-(\d+)?/);
                if (rangeMatch) {
                    const start = parseInt(rangeMatch[1]);
                    const end = rangeMatch[2] ? parseInt(rangeMatch[2]) : undefined;
                    offsetClause = `OFFSET ${start}`;
                    if (end !== undefined) {
                        limitClause = `LIMIT ${end - start + 1}`;
                    }
                }
            }
            
            // Explicit Limit/Offset override Range header
            if (limitParam) limitClause = `LIMIT ${parseInt(limitParam)}`;
            if (offsetParam) offsetClause = `OFFSET ${parseInt(offsetParam)}`;

            sql = `SELECT ${columns} FROM public.${safeTable} ${whereClause} ${orderBy} ${limitClause} ${offsetClause}`;
            
            // Count Query if requested (Supabase JS often requests this)
            if (headers['prefer'] && headers['prefer'].includes('count=exact')) {
                countQuery = `SELECT COUNT(*) as total FROM public.${safeTable} ${whereClause}`;
            }

        } else if (method === 'POST') {
            // INSERT
            const rows = Array.isArray(body) ? body : [body];
            if (rows.length === 0) throw new Error("No data to insert");

            const keys = Object.keys(rows[0]);
            const cols = keys.map(k => `"${k.replace(/"/g, '""')}"`).join(', ');
            
            // Build Values placeholders ($1, $2), ($3, $4)...
            const valueGroups: string[] = [];
            let paramIdx = 1;
            
            rows.forEach(row => {
                const placeholders: string[] = [];
                keys.forEach(k => {
                    placeholders.push(`$${paramIdx++}`);
                    params.push(row[k]);
                });
                valueGroups.push(`(${placeholders.join(', ')})`);
            });

            let upsertClause = '';
            // Basic Upsert Support (Prefer: resolution=merge-duplicates)
            if (headers['prefer'] && headers['prefer'].includes('resolution=merge-duplicates')) {
                // If on_conflict is specified, use it. Otherwise, assume ID.
                const conflictTarget = onConflictParam ? `"${onConflictParam.replace(/"/g, '""')}"` : '"id"';
                const updateSet = keys.map(k => `"${k.replace(/"/g, '""')}" = EXCLUDED."${k.replace(/"/g, '""')}"`).join(', ');
                upsertClause = `ON CONFLICT (${conflictTarget}) DO UPDATE SET ${updateSet}`;
            } else if (headers['prefer'] && headers['prefer'].includes('resolution=ignore-duplicates')) {
                upsertClause = `ON CONFLICT DO NOTHING`;
            }

            // Return representation?
            const returning = (headers['prefer'] && headers['prefer'].includes('return=minimal')) ? '' : 'RETURNING *';

            sql = `INSERT INTO public.${safeTable} (${cols}) VALUES ${valueGroups.join(', ')} ${upsertClause} ${returning}`;

        } else if (method === 'PATCH') {
            // UPDATE
            const keys = Object.keys(body);
            if (keys.length === 0) throw new Error("No data to update");

            const setClauses: string[] = [];
            keys.forEach(k => {
                setClauses.push(`"${k.replace(/"/g, '""')}" = $${params.length + 1}`);
                params.push(body[k]);
            });

            // Re-parse filters for WHERE clause because params array grew
            const updateFilters: string[] = [];
            
            Object.keys(query).forEach(key => {
                if (['select', 'order', 'limit', 'offset'].includes(key)) return;
                const value = query[key];
                const { clause, val } = this.parseFilter(key, value, params.length + 1);
                if (clause) {
                    updateFilters.push(clause);
                    if (val !== undefined) params.push(val);
                }
            });

            const updateWhere = updateFilters.length > 0 ? `WHERE ${updateFilters.join(' AND ')}` : '';
            // Safety: Block update without where unless explicitly allowed (not implemented to be safe)
            if (!updateWhere) throw new Error("UPDATE requires a filter (e.g. ?id=eq.1)");

            const returning = (headers['prefer'] && headers['prefer'].includes('return=representation')) ? 'RETURNING *' : '';

            sql = `UPDATE public.${safeTable} SET ${setClauses.join(', ')} ${updateWhere} ${returning}`;

        } else if (method === 'DELETE') {
            // DELETE
            const deleteFilters: string[] = [];
            Object.keys(query).forEach(key => {
                if (['select', 'order', 'limit', 'offset'].includes(key)) return;
                const value = query[key];
                const { clause, val } = this.parseFilter(key, value, params.length + 1);
                if (clause) {
                    deleteFilters.push(clause);
                    if (val !== undefined) params.push(val);
                }
            });

            const deleteWhere = deleteFilters.length > 0 ? `WHERE ${deleteFilters.join(' AND ')}` : '';
            if (!deleteWhere) throw new Error("DELETE requires a filter (e.g. ?id=eq.1)");

            const returning = (headers['prefer'] && headers['prefer'].includes('return=representation')) ? 'RETURNING *' : '';

            sql = `DELETE FROM public.${safeTable} ${deleteWhere} ${returning}`;
        }

        return { text: sql, values: params, countQuery };
    }

    private static parseSelect(selectParam: string): string {
        if (!selectParam || selectParam === '*' || selectParam === '%2A') return '*';
        
        // Handle Aliases (col:alias) and JSON operators
        return selectParam.split(',').map(c => {
            const part = c.trim();
            
            // Alias: name:full_name -> "name" AS "full_name"
            if (part.includes(':') && !part.includes('::')) { // Avoid cast operator conflicts
                const [col, alias] = part.split(':');
                return `"${col.trim()}" AS "${alias.trim()}"`;
            }

            // Basic protection: allow alphanumeric, underscore, dot, asterisk, arrow
            if (/^[a-zA-Z0-9_\.\*\->]+$/.test(part)) {
                // If it contains special chars (JSON op), assume valid but don't auto-quote
                if (part.includes('->') || part.includes('.')) return part;
                return `"${part}"`;
            }
            
            return part; // Fallback
        }).join(', ');
    }

    private static parseOrder(orderParam: string): string {
        if (!orderParam) return '';
        // Format: age.desc,name.asc
        const parts = orderParam.split(',');
        const orders = parts.map(p => {
            const [col, dir] = p.split('.');
            const safeCol = `"${col.replace(/"/g, '')}"`;
            const safeDir = (dir && dir.toLowerCase() === 'desc') ? 'DESC' : 'ASC';
            // Handle nullsfirst / nullslast
            let nulls = '';
            if (p.includes('nullsfirst')) nulls = ' NULLS FIRST';
            if (p.includes('nullslast')) nulls = ' NULLS LAST';
            return `${safeCol} ${safeDir}${nulls}`;
        });
        return `ORDER BY ${orders.join(', ')}`;
    }

    private static parseFilter(key: string, value: string, paramIndex: number): { clause: string, val: any } {
        const parts = value.split('.');
        if (parts.length < 2) {
            // Default to equality if no operator provided
            // e.g. ?id=1 becomes id=eq.1
            const column = `"${key.replace(/"/g, '')}"`;
            return { clause: `${column} = $${paramIndex}`, val: value };
        }

        const op = parts[0];
        const rawVal = parts.slice(1).join('.'); // Re-join rest in case value has dots
        const column = `"${key.replace(/"/g, '')}"`;

        switch (op) {
            case 'eq': return { clause: `${column} = $${paramIndex}`, val: rawVal };
            case 'neq': return { clause: `${column} != $${paramIndex}`, val: rawVal };
            case 'gt': return { clause: `${column} > $${paramIndex}`, val: rawVal };
            case 'gte': return { clause: `${column} >= $${paramIndex}`, val: rawVal };
            case 'lt': return { clause: `${column} < $${paramIndex}`, val: rawVal };
            case 'lte': return { clause: `${column} <= $${paramIndex}`, val: rawVal };
            case 'like': return { clause: `${column} LIKE $${paramIndex}`, val: rawVal.replace(/\*/g, '%') };
            case 'ilike': return { clause: `${column} ILIKE $${paramIndex}`, val: rawVal.replace(/\*/g, '%') };
            case 'is': 
                if (rawVal === 'null') return { clause: `${column} IS NULL`, val: undefined };
                if (rawVal === 'true') return { clause: `${column} IS TRUE`, val: undefined };
                if (rawVal === 'false') return { clause: `${column} IS FALSE`, val: undefined };
                return { clause: '', val: undefined };
            case 'in':
                // rawVal is like (1,2,3) or ("a","b")
                // Remove parens
                const cleanVal = rawVal.replace(/^\(/, '').replace(/\)$/, '');
                // Split by comma
                const arr = cleanVal.split(',').map(v => v.replace(/^"|"$/g, '')); 
                // For IN, we return array to be spread into params
                return { clause: `${column} = ANY($${paramIndex})`, val: arr };
            case 'cs': // contains (json/array)
                return { clause: `${column} @> $${paramIndex}`, val: rawVal };
            case 'cd': // contained by
                return { clause: `${column} <@ $${paramIndex}`, val: rawVal };
            default:
                // Fallback: treat whole value as equality match
                return { clause: `${column} = $${paramIndex}`, val: value };
        }
    }
}
