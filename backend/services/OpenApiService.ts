import { Pool } from 'pg';
import { URL } from 'url';

export class OpenApiService {
    
    /**
     * Generates standard OpenAPI spec for Cascata Native API (Internal Dashboard)
     */
    public static async generate(projectSlug: string, dbName: string, projectPool: Pool, baseUrl: string) {
        return this.buildNativeSpec(projectSlug, projectPool, baseUrl);
    }

    /**
     * Generates PostgREST-compatible Swagger 2.0 spec for FlutterFlow
     * Strictly mimics Supabase response structure, type mapping, and formatting.
     */
    public static async generatePostgrest(projectSlug: string, dbName: string, projectPool: Pool, baseUrl: string) {
        return this.buildSwagger2Spec(projectSlug, projectPool, baseUrl);
    }

    // --- SWAGGER 2.0 BUILDER (PostgREST/Supabase Clone) ---
    private static async buildSwagger2Spec(projectSlug: string, pool: Pool, baseUrl: string) {
        const tables = await this.getTables(pool);
        
        // CORRECTION: Parse URL to strictly separate host and basePath
        // This prevents FlutterFlow from malforming the final API URL
        let hostStr = 'localhost';
        let basePathStr = '/';
        let schemesList = ['http'];

        try {
            // Add protocol if missing for parsing
            const urlToParse = baseUrl.startsWith('http') ? baseUrl : `http://${baseUrl}`;
            const parsed = new URL(urlToParse);
            
            hostStr = parsed.host; // includes port if present
            basePathStr = parsed.pathname; // includes /api/data/.../rest/v1
            schemesList = [parsed.protocol.replace(':', '')];
            
            // Remove trailing slash from basePath to avoid double slashes in generated paths
            if (basePathStr.endsWith('/') && basePathStr.length > 1) {
                basePathStr = basePathStr.slice(0, -1);
            }
        } catch (e) {
            console.warn('[OpenAPI] Failed to parse baseUrl, falling back to defaults', e);
        }

        const spec: any = {
            swagger: "2.0",
            info: {
                description: "Standard public schema API",
                title: "standard public schema",
                version: "12.0.2" // PostgREST version emulation
            },
            host: hostStr,
            basePath: basePathStr,
            schemes: schemesList,
            consumes: [
                "application/json",
                "application/vnd.pgrst.object+json;nulls=stripped",
                "application/vnd.pgrst.object+json",
                "text/csv"
            ],
            produces: [
                "application/json",
                "application/vnd.pgrst.object+json;nulls=stripped",
                "application/vnd.pgrst.object+json",
                "text/csv"
            ],
            paths: {
                "/": {
                    get: {
                        produces: ["application/openapi+json", "application/json"],
                        responses: { "200": { description: "OK" } },
                        summary: "OpenAPI description (this document)",
                        tags: ["Introspection"]
                    }
                }
            },
            definitions: {},
            parameters: {
                // Standard PostgREST Parameters
                select: { name: "select", description: "Filtering Columns", required: false, in: "query", type: "string" },
                order: { name: "order", description: "Ordering", required: false, in: "query", type: "string" },
                limit: { name: "limit", description: "Limiting and Pagination", required: false, in: "query", type: "integer" },
                offset: { name: "offset", description: "Limiting and Pagination", required: false, in: "query", type: "integer" },
                on_conflict: { name: "on_conflict", description: "On Conflict", required: false, in: "query", type: "string" },
                range: { name: "Range", description: "Limiting and Pagination", required: false, in: "header", type: "string" },
                rangeUnit: { name: "Range-Unit", description: "Limiting and Pagination", required: false, default: "items", in: "header", type: "string" },
                preferReturn: { 
                    name: "Prefer", description: "Preference", required: false, in: "header", type: "string",
                    enum: ["return=representation", "return=minimal", "return=none"] 
                },
                preferCount: {
                    name: "Prefer", description: "Preference", required: false, in: "header", type: "string",
                    enum: ["count=none"]
                },
                preferPost: {
                    name: "Prefer", description: "Preference", required: false, in: "header", type: "string",
                    enum: ["return=representation", "return=minimal", "return=none", "resolution=ignore-duplicates", "resolution=merge-duplicates"]
                }
            }
        };

        // Build Table Definitions & Paths
        for (const table of tables) {
            const columns = await this.getColumns(pool, table);
            
            // 1. Definition (Schema)
            const properties: any = {};
            const required: string[] = [];

            columns.forEach((col: any) => {
                const typeMap = this.mapPgTypeToSwagger(col);
                
                properties[col.name] = {
                    type: typeMap.type,
                    format: typeMap.format, // Uses Postgres type name (e.g. 'numeric', 'timestamp without time zone')
                    description: this.buildDescription(col)
                };

                // Add Defaults (Supabase behavior)
                if (col.column_default !== null) {
                    // Clean up default string (e.g. 'now()', '0', 'true')
                    let defVal = col.column_default;
                    // Try to cast basic types
                    if (typeMap.type === 'integer' || typeMap.type === 'number') {
                        const num = Number(defVal.replace(/::.*/, '').replace(/'/g, ''));
                        if (!isNaN(num)) defVal = num;
                    } else if (typeMap.type === 'boolean') {
                        defVal = defVal === 'true';
                    }
                    properties[col.name].default = defVal;
                }

                // Add Items for arrays
                if (typeMap.type === 'array' && typeMap.items) {
                    properties[col.name].items = typeMap.items;
                }
                
                // Determine Required Fields
                // PKs are always required in definitions for Supabase/PostgREST
                // Also fields that are NOT NULL and have NO DEFAULT
                if (col.is_primary_key || (col.is_nullable === 'NO' && !col.column_default)) {
                    required.push(col.name);
                }

                // 2. RowFilter Parameters
                // PostgREST treats all filters as strings in Swagger (e.g. id=eq.1)
                spec.parameters[`rowFilter.${table}.${col.name}`] = {
                    name: col.name,
                    required: false,
                    in: "query",
                    type: "string",
                    format: typeMap.format, // Pass format hint
                    description: `Filter ${table} by ${col.name}`
                };
            });

            spec.definitions[table] = {
                type: "object",
                properties,
                required: required.length > 0 ? required : undefined
            };

            // 3. Body Parameter Reference
            spec.parameters[`body.${table}`] = {
                name: table,
                description: table,
                required: false,
                in: "body",
                schema: { $ref: `#/definitions/${table}` }
            };

            // 4. Paths
            const rowFilters = columns.map((c: any) => ({ $ref: `#/parameters/rowFilter.${table}.${c.name}` }));

            spec.paths[`/${table}`] = {
                get: {
                    tags: [table],
                    parameters: [
                        ...rowFilters,
                        { $ref: "#/parameters/select" },
                        { $ref: "#/parameters/order" },
                        { $ref: "#/parameters/range" },
                        { $ref: "#/parameters/rangeUnit" },
                        { $ref: "#/parameters/offset" },
                        { $ref: "#/parameters/limit" },
                        { $ref: "#/parameters/preferCount" }
                    ],
                    responses: {
                        "200": {
                            description: "OK",
                            schema: {
                                type: "array",
                                items: { $ref: `#/definitions/${table}` }
                            }
                        },
                        "206": { description: "Partial Content" }
                    }
                },
                post: {
                    tags: [table],
                    parameters: [
                        { $ref: `#/parameters/body.${table}` },
                        { $ref: "#/parameters/select" },
                        { $ref: "#/parameters/preferPost" }
                    ],
                    responses: { "201": { description: "Created" } }
                },
                patch: {
                    tags: [table],
                    parameters: [
                        ...rowFilters,
                        { $ref: `#/parameters/body.${table}` },
                        { $ref: "#/parameters/preferReturn" }
                    ],
                    responses: { "204": { description: "No Content" } }
                },
                delete: {
                    tags: [table],
                    parameters: [
                        ...rowFilters,
                        { $ref: "#/parameters/preferReturn" }
                    ],
                    responses: { "204": { description: "No Content" } }
                }
            };
        }

        return spec;
    }

    // --- OPENAPI 3.0 BUILDER (Native Dashboard) ---
    private static async buildNativeSpec(projectSlug: string, pool: Pool, baseUrl: string) {
        const tables = await this.getTables(pool);
        const paths: any = {};
        const schemas: any = {};

        for (const table of tables) {
            const columns = await this.getColumns(pool, table);
            
            schemas[table] = {
                type: 'object',
                properties: columns.reduce((acc: any, col: any) => {
                    const typeDef = this.mapPgTypeToSwagger(col);
                    acc[col.name] = { type: typeDef.type, format: typeDef.format };
                    return acc;
                }, {})
            };

            paths[`/tables/${table}/data`] = {
                get: {
                    summary: `List ${table}`,
                    tags: [table],
                    responses: { '200': { description: 'OK', content: { 'application/json': { schema: { type: 'array', items: { $ref: `#/components/schemas/${table}` } } } } } }
                }
            };
        }

        return {
            openapi: '3.0.0',
            info: { title: `${projectSlug} API`, version: '1.0.0' },
            servers: [{ url: baseUrl }],
            paths,
            components: { schemas }
        };
    }

    // --- HELPERS ---

    private static async getTables(pool: Pool) {
        const res = await pool.query(`
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_type = 'BASE TABLE'
            AND table_name NOT LIKE '_deleted_%'
        `);
        return res.rows.map(r => r.table_name);
    }

    /**
     * Gets column details using pg_catalog for robust PK detection.
     * information_schema can be flaky with redundant UNIQUE constraints.
     */
    private static async getColumns(pool: Pool, table: string) {
        const res = await pool.query(`
            SELECT 
                a.attname as name,
                t.typname as udt_name,
                CASE WHEN a.attnotnull THEN 'NO' ELSE 'YES' END as is_nullable,
                pg_get_expr(d.adbin, d.adrelid) as column_default,
                COALESCE(i.indisprimary, false) as is_primary_key
            FROM pg_attribute a
            JOIN pg_class c ON c.oid = a.attrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            JOIN pg_type t ON a.atttypid = t.oid
            LEFT JOIN pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum
            LEFT JOIN pg_index i ON i.indrelid = c.oid AND i.indisprimary AND a.attnum = ANY(i.indkey)
            WHERE 
                n.nspname = 'public' 
                AND c.relname = $1
                AND a.attnum > 0 
                AND NOT a.attisdropped
            ORDER BY a.attnum
        `, [table]);

        return res.rows;
    }

    private static buildDescription(col: any): string {
        // PostgREST/FlutterFlow recognition magic string
        let desc = '';
        
        // If the database says it's a PK (via pg_index check), mark it.
        if (col.is_primary_key) {
             desc = 'Note:\nThis is a Primary Key.<pk/>';
        }
        return desc;
    }

    /**
     * Maps PostgreSQL Types to Swagger 2.0 Types/Formats.
     * Uses "Pass-through" formatting where possible to match Supabase.
     */
    private static mapPgTypeToSwagger(col: any): { type: string, format: string, items?: any } {
        const udt = col.udt_name.toLowerCase(); 

        // 1. Integers
        if (['int2', 'smallint'].includes(udt)) {
            return { type: 'integer', format: 'smallint' };
        }
        if (['int4', 'integer', 'serial', 'serial4'].includes(udt)) {
            return { type: 'integer', format: 'integer' }; 
        }
        if (['int8', 'bigint', 'bigserial', 'serial8'].includes(udt)) {
            return { type: 'integer', format: 'bigint' };
        }

        // 2. Floating Point / Numeric
        if (['numeric', 'decimal'].includes(udt)) {
            return { type: 'number', format: 'numeric' };
        }
        if (['real', 'float4'].includes(udt)) {
            return { type: 'number', format: 'real' };
        }
        if (['double precision', 'float8'].includes(udt)) {
            return { type: 'number', format: 'double precision' };
        }
        if (['money'].includes(udt)) {
            return { type: 'number', format: 'money' };
        }

        // 3. Booleans
        if (['bool', 'boolean'].includes(udt)) {
            return { type: 'boolean', format: 'boolean' };
        }

        // 4. Dates & Times
        if (udt === 'timestamp' || udt === 'timestamp without time zone') {
            return { type: 'string', format: 'timestamp without time zone' };
        }
        if (udt === 'timestamptz' || udt === 'timestamp with time zone') {
            return { type: 'string', format: 'timestamp with time zone' };
        }
        if (udt === 'date') {
            return { type: 'string', format: 'date' };
        }
        if (udt === 'time' || udt === 'time without time zone') {
            return { type: 'string', format: 'time without time zone' };
        }

        // 5. UUID
        if (udt === 'uuid') {
            return { type: 'string', format: 'uuid' };
        }

        // 6. JSON
        if (['json', 'jsonb'].includes(udt)) {
            return { type: 'object', format: 'json' };
        }

        // 7. Arrays (Recursive)
        if (udt.startsWith('_')) {
            const innerUdt = udt.substring(1);
            const innerMap = this.mapPgTypeToSwagger({ udt_name: innerUdt });
            return { 
                type: 'array', 
                format: udt,
                items: { type: innerMap.type, format: innerMap.format } 
            };
        }

        // 8. Text/Default
        return { type: 'string', format: 'text' };
    }
}
