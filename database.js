/**
 * @file database.js
 * @description Módulo de inicialização e estruturação do banco de dados SQLite corporativo com suporte ao Módulo de Compras e Celulares.
 * @author TI Tracbel
 */

const sqlite3 = require('sqlite3');
const { open } = require('sqlite');

async function iniciarBanco() {
    try {
        const db = await open({
            filename: './inventario_tracbel.db',
            driver: sqlite3.Database
        });

        await db.get('PRAGMA foreign_keys = ON;');

        // 1. TABELA DE ATIVOS (Computadores)
        await db.exec(`
            CREATE TABLE IF NOT EXISTS ativos (
                service_tag TEXT PRIMARY KEY NOT NULL,
                empresa TEXT,
                entrega TEXT,
                filial_atual TEXT,
                tipo TEXT,
                modelo TEXT,
                colaborador TEXT,
                duplicado TEXT,
                status TEXT,
                cargo TEXT,
                ultimo_colaborador TEXT,
                multi_usuario TEXT,
                observacao TEXT,
                service_tag_monitor TEXT,
                cc TEXT,
                cc_contab TEXT,
                desc_cc_contab TEXT,
                emp_colab TEXT,
                filial_colab TEXT,
                filial_rh_corrigido TEXT,
                coluna2 TEXT,
                cc_dif TEXT,
                filial_dif TEXT,
                nf_transf TEXT,
                filial_dest_transf TEXT,
                order_sale TEXT,
                remessa TEXT,
                contrato TEXT,
                patrimonio TEXT,
                envio_dell TEXT,
                fim_garantia TEXT,
                reportado_inventario TEXT,
                usuario_inventario TEXT,
                memoria TEXT,
                memoria_adicional TEXT,
                localizacao TEXT,
                troca_chg_2_leva_2025 TEXT,
                x TEXT
            );
        `);

        // 2. CONTROLE DE ACESSO (RBAC)
        await db.exec(`
            CREATE TABLE IF NOT EXISTS usuarios_permissoes (
                email TEXT PRIMARY KEY NOT NULL,
                role TEXT DEFAULT 'user' NOT NULL
            );
        `);

        // 3. MÓDULO DE COMPRAS TI
        await db.exec(`
            CREATE TABLE IF NOT EXISTS solicitacoes_compras (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data_solicitacao TEXT NOT NULL,
                solicitante_email TEXT NOT NULL,
                chamado TEXT,
                quantidade INTEGER NOT NULL DEFAULT 1,
                equipamentos TEXT NOT NULL,
                filial TEXT NOT NULL,
                setor TEXT,
                beneficiado TEXT,
                status_gerente TEXT DEFAULT 'PENDENTE' NOT NULL,
                status_logistica TEXT DEFAULT 'Aguardando Aprovação' NOT NULL,
                data_envio_instalacao TEXT,
                numero_oc TEXT,
                FOREIGN KEY (solicitante_email) REFERENCES usuarios_permissoes(email)
            );
        `);

        // 4. TABELA DE CELULARES (baseada na planilha)
        await db.exec(`
            CREATE TABLE IF NOT EXISTS celulares (
                imei TEXT PRIMARY KEY NOT NULL,
                modelo TEXT,
                marca TEXT,
                numero_linha TEXT,
                colaborador TEXT,
                status TEXT DEFAULT 'Ativo',
                emp_destino TEXT,
                filial_destino TEXT,
                assinou_termo TEXT,
                mu TEXT,
                fone TEXT,
                carregador TEXT,
                cabo TEXT,
                obs TEXT,
                conforme_orcamento TEXT,
                coluna1 TEXT,
                data_entrega TEXT,
                data_vencimento_garantia TEXT,
                patrimonio TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 5. ADMINISTRADORES MASTERS DO .ENV
        const emailsDoAmbiente = process.env.ADMIN_MASTERS || '';
        const administradoresIniciais = emailsDoAmbiente.split(',').map(email => email.trim());

        for (const email of administradoresIniciais) {
            if (email && email.includes('@')) {
                await db.run(`
                    INSERT OR IGNORE INTO usuarios_permissoes (email, role) 
                    VALUES (?, 'admin');
                `, [email.toLowerCase()]);
            }
        }

        console.log("🗄️ [BANCO DE DADOS] Tabelas do Inventário, Compras e Celulares prontas.");
        return db;

    } catch (error) {
        console.error("🚨 [ERRO CRÍTICO] Falha ao inicializar o banco de dados SQLite:", error.message);
        throw error;
    }
}

module.exports = iniciarBanco;