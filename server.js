/**
 * @file server.js
 * @description Servidor Express blindado e otimizado com controle de RBAC via Firebase, SQLite, Tratador de Datas do Excel, Gestão de Usuários e Módulo de Celulares.
 * @author TI Tracbel
 */

require('dotenv').config();

const express = require('express');
const multer = require('multer');
const xlsx = require('xlsx');
const fs = require('fs');
const admin = require('firebase-admin');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const iniciarBanco = require('./database');

const app = express();
app.use(express.json());

app.use(helmet({ contentSecurityPolicy: false }));

const limitadorSeguranca = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: '⚠️ Muitas requisições vindas deste Host. Tente novamente mais tarde por segurança.' },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limitadorSeguranca);

const arquivoChaveFirebase = require('./c-fk.json');
admin.initializeApp({ credential: admin.credential.cert(arquivoChaveFirebase) });
console.log("🔒 Firebase Admin ativo com permissões dinâmicas via Banco de Dados.");

const verificarTokenFirebase = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Acesso negado. Token ausente.' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const usuarioDecodificado = await admin.auth().verifyIdToken(token);
        req.usuarioLogado = usuarioDecodificado;
        
        const emailUsuario = usuarioDecodificado.email ? usuarioDecodificado.email.toLowerCase().trim() : '';
        
        let permissaoNoBanco = await db.get('SELECT role FROM usuarios_permissoes WHERE email = ?', [emailUsuario]);
        
        if (!permissaoNoBanco) {
            await db.run('INSERT INTO usuarios_permissoes (email, role) VALUES (?, ?)', [emailUsuario, 'pendente']);
            permissaoNoBanco = { role: 'pendente' };
        }

        if (permissaoNoBanco.role === 'pendente') {
            return res.status(403).json({ 
                error: 'PENDENTE_APROVACAO', 
                mensagem: 'Seu e-mail corporativo foi registrado no sistema. Por favor, solicite a aprovação do seu acesso junto ao Administrador de TI.' 
            });
        }

        req.usuarioLogado.isAdmin = (permissaoNoBanco && permissaoNoBanco.role === 'admin');
        
        const emailMascarado = emailUsuario.replace(/(..)(.*)(@.*)/, "$1***$3");
        console.log(`👤 Conexão SSO: ${emailMascarado} | Nível Administrador: ${req.usuarioLogado.isAdmin}`);
        
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Sessão expirada. Faça login novamente.' });
    }
};

app.get('/api/config/firebase', (req, res) => {
    res.json({
        apiKey: process.env.FIREBASE_API_KEY,
        authDomain: process.env.FIREBASE_AUTH_DOMAIN,
        projectId: process.env.FIREBASE_PROJECT_ID,
        storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
        messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
        appId: process.env.FIREBASE_APP_ID,
        measurementId: process.env.FIREBASE_MEASUREMENT_ID
    });
});

app.use(express.static('public')); 
app.use('/api', verificarTokenFirebase);

const INSTANCIA_SERVIDOR_ID = String(Date.now() + Math.random());

app.get('/api/config/instancia', (req, res) => {
    res.json({ instanciaId: INSTANCIA_SERVIDOR_ID });
});

const upload = multer({ 
    dest: 'uploads/',
    limits: { fileSize: 15 * 1024 * 1024 } 
});

let db;

const calcularDiferenca = (dataObj) => {
    if (!dataObj || isNaN(dataObj.getTime())) return 'N/A';
    try {
        const hoje = new Date();
        const meses = Math.floor((hoje - dataObj) / (1000 * 60 * 60 * 24 * 30.41));
        return meses < 12 ? `${Math.abs(meses)} meses` : `${Math.abs((meses / 12).toFixed(1))} anos`;
    } catch (err) { return 'N/A'; }
};

iniciarBanco().then((database) => { 
    db = database; 
    const PORTA = process.env.PORT || 3000;
    app.listen(PORTA, '0.0.0.0', () => { 
        console.log(`🚀 Servidor Tracbel ativo na rede local! Porta: ${PORTA}`);
    });
});

// ==========================================================================
// ROTAS DA API
// ==========================================================================

app.get('/api/auth/perfil', (req, res) => {
    res.json({
        email: req.usuarioLogado.email,
        uid: req.usuarioLogado.uid,
        isAdmin: req.usuarioLogado.isAdmin
    });
});

// ==========================================================================
// GESTÃO DE USUÁRIOS
// ==========================================================================

app.get('/api/usuarios', async (req, res) => {
    if (!req.usuarioLogado.isAdmin) return res.status(403).json({ error: 'Permissão negada.' });
    try {
        const usuarios = await db.all(`
            SELECT email, role FROM usuarios_permissoes 
            ORDER BY CASE WHEN role = 'pendente' THEN 0 ELSE 1 END, email ASC
        `);
        res.json(usuarios);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/usuarios/role', async (req, res) => {
    if (!req.usuarioLogado.isAdmin) return res.status(403).json({ error: 'Apenas administradores gerenciam permissões.' });
    try {
        const { email, novaRole } = req.body;
        if (!email || !novaRole) return res.status(400).json({ error: 'Dados incompletos.' });

        const emailAlvo = email.toLowerCase().trim();

        if (emailAlvo === req.usuarioLogado.email.toLowerCase() && novaRole !== 'admin') {
            return res.status(400).json({ error: '🚨 Operação revogada: Você não pode retirar seu próprio privilégio de Administrador!' });
        }

        await db.run(`
            INSERT INTO usuarios_permissoes (email, role) VALUES (?, ?)
            ON CONFLICT(email) DO UPDATE SET role = excluded.role
        `, [emailAlvo, novaRole]);

        res.json({ mensagem: `Permissão de ${emailAlvo} reconfigurada para ${novaRole.toUpperCase()} com sucesso!` });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/usuarios/rejeitar', async (req, res) => {
    if (!req.usuarioLogado.isAdmin) return res.status(403).json({ error: 'Acesso negado. Apenas administradores podem rejeitar acessos.' });
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'E-mail não informado.' });
        const emailAlvo = email.toLowerCase().trim();

        const resultado = await db.run('DELETE FROM usuarios_permissoes WHERE email = ? AND role = ?', [emailAlvo, 'pendente']);
        if (resultado.changes === 0) {
            return res.status(404).json({ error: 'Usuário pendente não encontrado ou já processado.' });
        }

        res.json({ mensagem: `Solicitação de ${emailAlvo} rejeitada e removida com sucesso!` });
    } catch (e) { res.status(500).json({ error: 'Erro interno ao rejeitar: ' + e.message }); }
});

app.delete('/api/usuarios/excluir', async (req, res) => {
    if (!req.usuarioLogado.isAdmin) return res.status(403).json({ error: 'Acesso negado. Recurso restrito a Administradores de TI.' });
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'E-mail não informado.' });
        const emailAlvo = email.toLowerCase().trim();

        if (emailAlvo === req.usuarioLogado.email.toLowerCase()) {
            return res.status(400).json({ error: '🚨 Bloqueio Crítico: Você não pode remover o seu próprio usuário logado!' });
        }

        const resultado = await db.run("DELETE FROM usuarios_permissoes WHERE email = ? AND role != 'pendente'", [emailAlvo]);
        if (resultado.changes === 0) {
            return res.status(404).json({ error: 'Usuário ativo não localizado no banco de dados.' });
        }

        res.json({ mensagem: `Sucesso! O acesso de ${emailAlvo} foi permanentemente revogado do inventário.` });
    } catch (e) { res.status(500).json({ error: 'Erro ao revogar acesso ativo: ' + e.message }); }
});

// ==========================================================================
// ATIVOS (COMPUTADORES)
// ==========================================================================

app.get('/api/ativos', async (req, res) => {
    try {
        const dados = await db.all('SELECT * FROM ativos');
        const hoje = new Date();
        const hojeZerado = new Date(hoje.getFullYear(), hoje.getMonth(), hoje.getDate());

        let countExpiradas = 0;
        let countDisponiveis = 0;

        const formatarParaDataReal = (valorRaw) => {
            if (!valorRaw || String(valorRaw).trim() === "" || String(valorRaw).includes('1899')) return null;
            const valorLimpo = String(valorRaw).trim();
            
            if (!isNaN(valorLimpo) && valorLimpo.length > 4) {
                const dataConvertida = new Date((Number(valorLimpo) - 25569) * 86400 * 1000);
                if (!isNaN(dataConvertida.getTime())) return dataConvertida;
            }
            if (valorLimpo.includes('/')) {
                const partes = valorLimpo.split('/');
                if (partes.length === 3) {
                    const ano = partes[2].length === 2 ? `20${partes[2]}` : partes[2];
                    return new Date(`${ano}-${partes[1]}-${partes[0]}T12:00:00`);
                }
            }
            if (valorLimpo.includes('-')) {
                const dataT = new Date(`${valorLimpo}T12:00:00`);
                if (!isNaN(dataT.getTime())) return dataT;
            }
            return null;
        };

        const dadosCalculados = dados.map(ativo => {
            const dataEnvioObj = formatarParaDataReal(ativo.envio_dell);
            const dataGarantiaObj = formatarParaDataReal(ativo.fim_garantia);

            let statusGarantia = "Sem informação";
            let diasRestantes = "N/A";

            if (dataGarantiaObj) {
                const fimZerado = new Date(dataGarantiaObj.getFullYear(), dataGarantiaObj.getMonth(), dataGarantiaObj.getDate());
                const diferencaTempo = fimZerado.getTime() - hojeZerado.getTime();
                const diferencaDias = Math.ceil(diferencaTempo / (1000 * 60 * 60 * 24));

                if (diferencaDias <= 0) {
                    statusGarantia = "⚠️ EXPIRADA";
                    countExpiradas++;
                    diasRestantes = `Expirou há ${Math.abs(diferencaDias)} dias`;
                } else {
                    statusGarantia = "Válida";
                    diasRestantes = `${diferencaDias} dias restantes`;
                }
            }

            const colaboradorTexto = ativo.colaborador ? String(ativo.colaborador).trim().toLowerCase() : '';
            const colaboradorSemAcento = colaboradorTexto.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
            if (colaboradorSemAcento === "3. disponivel na filial" || colaboradorSemAcento.includes("disponivel na filial")) {
                countDisponiveis++;
            }

            return {
                ...ativo,
                envio_dell: dataEnvioObj ? dataEnvioObj.toLocaleDateString('pt-BR') : (ativo.envio_dell || '-'),
                fim_garantia: dataGarantiaObj ? dataGarantiaObj.toLocaleDateString('pt-BR') : (ativo.fim_garantia || '-'),
                tempo_computador: calcularDiferenca(dataEnvioObj),
                tempo_garantia: calcularDiferenca(dataGarantiaObj),
                garantia_status_real: statusGarantia,
                dias_para_vencer: diasRestantes
            };
        });

        const comprasPendentes = await db.get("SELECT COUNT(*) as qtd FROM solicitacoes_compras WHERE status_gerente = 'PENDENTE'");
        const mesAtualStr = String(hoje.getMonth() + 1).padStart(2, '0');
        const comprasAprovadasMes = await db.get(`
            SELECT COUNT(*) as qtd FROM solicitacoes_compras 
            WHERE status_gerente = 'APROVADO' 
            AND strftime('%m', data_solicitacao) = ?
        `, [mesAtualStr]);

        const distribuicaoEmpresas = await db.all(`
            SELECT empresa, COUNT(*) as quantidade FROM ativos 
            WHERE empresa IS NOT NULL AND empresa != ''
            GROUP BY empresa ORDER BY quantidade DESC
        `);

        res.json({
            ativos: dadosCalculados,
            total: dadosCalculados.length,
            expiradas: countExpiradas,
            disponiveis: countDisponiveis,
            comprasPendentes: comprasPendentes.qtd || 0,
            comprasMes: comprasAprovadasMes.qtd || 0,
            graficoEmpresas: distribuicaoEmpresas
        });
    } catch (error) { 
        res.status(500).json({ error: error.message }); 
    }
});

app.post('/api/ativos', async (req, res) => {
    if (!req.usuarioLogado.isAdmin) return res.status(403).json({ error: 'Permissão negada. Apenas administradores.' });
    try {
        const d = req.body;
        if (!d.service_tag || String(d.service_tag).trim() === "") {
            return res.status(400).json({ error: 'Service Tag é obrigatória e não pode ser vazia.' });
        }

        await db.run(`
            INSERT INTO ativos (
                service_tag, empresa, entrega, filial_atual, tipo, modelo, colaborador, 
                duplicado, status, cargo, ultimo_colaborador, multi_usuario, observacao, 
                service_tag_monitor, cc, cc_contab, desc_cc_contab, emp_colab, filial_colab, 
                filial_rh_corrigido, coluna2, cc_dif, filial_dif, nf_transf, filial_dest_transf, 
                order_sale, remessa, contrato, patrimonio, envio_dell, fim_garantia, 
                reportado_inventario, usuario_inventario, memoria, memoria_adicional, 
                localizacao, troca_chg_2_leva_2025, x
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        `, [
            d.service_tag.trim().toUpperCase(), d.empresa, d.entrega, d.filial_atual, d.tipo, d.modelo, d.colaborador,
            d.duplicado, d.status, d.cargo, d.ultimo_colaborador, d.multi_usuario, d.observacao,
            d.service_tag_monitor, d.cc, d.cc_contab, d.desc_cc_contab, d.emp_colab, d.filial_colab,
            d.filial_rh_corrigido, d.coluna2, d.cc_dif, d.filial_dif, d.nf_transf, d.filial_dest_transf,
            d.order_sale, d.remessa, d.contrato, d.patrimonio, d.envio_dell, d.fim_garantia,
            d.reportado_inventario, d.usuario_inventario, d.memoria, d.memoria_adicional, d.localizacao,
            d.troca_chg_2_leva_2025, d.x
        ]);
        res.status(201).json({ mensagem: 'Sucesso' });
    } catch (e) { res.status(500).json({ error: 'Service Tag duplicada ou erro interno de integridade.' }); }
});

app.put('/api/ativos/:service_tag', async (req, res) => {
    if (!req.usuarioLogado.isAdmin) return res.status(403).json({ error: 'Permissão negada. Apenas administradores.' });
    try {
        const { service_tag } = req.params;
        const d = req.body;
        const tagChave = String(service_tag).trim().toUpperCase();

        const resultado = await db.run(`
            UPDATE ativos SET 
                empresa=?, entrega=?, filial_atual=?, tipo=?, modelo=?, colaborador=?, duplicado=?, 
                status=?, cargo=?, ultimo_colaborador=?, multi_usuario=?, observacao=?, service_tag_monitor=?, 
                cc=?, cc_contab=?, desc_cc_contab=?, emp_colab=?, filial_colab=?, filial_rh_corrigido=?, 
                coluna2=?, cc_dif=?, filial_dif=?, nf_transf=?, filial_dest_transf=?, order_sale=?, 
                remessa=?, contrato=?, patrimonio=?, envio_dell=?, fim_garantia=?, reportado_inventario=?, 
                usuario_inventario=?, memoria=?, memoria_adicional=?, localizacao=?, troca_chg_2_leva_2025=?, x=?
            WHERE service_tag = ?
        `, [
            d.empresa, d.entrega, d.filial_atual, d.tipo, d.modelo, d.colaborador, d.duplicado,
            d.status, d.cargo, d.ultimo_colaborador, d.multi_usuario, d.observacao, d.service_tag_monitor,
            d.cc, d.cc_contab, d.desc_cc_contab, d.emp_colab, d.filial_colab, d.filial_rh_corrigido,
            d.coluna2, d.cc_dif, d.filial_dif, d.nf_transf, d.filial_dest_transf, d.order_sale,
            d.remessa, d.contrato, d.patrimonio, d.envio_dell, d.fim_garantia, d.reportado_inventario,
            d.usuario_inventario, d.memoria, d.memoria_adicional, d.localizacao, d.troca_chg_2_leva_2025, d.x,
            tagChave
        ]);

        if (resultado.changes === 0) {
            return res.status(404).json({ error: 'Ativo não encontrado para atualização.' });
        }
        res.json({ mensagem: 'Registro updated com sucesso!' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/ativos/importar', upload.single('planilha'), async (req, res) => {
    if (!req.usuarioLogado.isAdmin) {
        if (req.file) fs.unlinkSync(req.file.path); 
        return res.status(403).json({ error: 'Apenas administradores podem fazer isso.' });
    }
    try {
        if (!req.file) return res.status(400).json({ error: 'Arquivo ausente.' });
        
        const workbook = xlsx.readFile(req.file.path, { codepage: 65001 });
        const nomeAbaAlvo = workbook.SheetNames.includes('Dados') ? 'Dados' : workbook.SheetNames[0];
        const dadosJson = xlsx.utils.sheet_to_json(workbook.Sheets[nomeAbaAlvo]);
        
        let sucesso = 0, falhas = 0;
        for (let rawRow of dadosJson) {
            const row = {};
            Object.keys(rawRow).forEach(key => { row[key.replace(/\r?\n|\r/g, " ").trim().toLowerCase()] = rawRow[key]; });
            const tag = row['service tag'];
            if (!tag || String(tag).trim() === "" || String(tag).toLowerCase().includes('service tag')) continue;
            try {
                await db.run(`
                    INSERT INTO ativos (
                        service_tag, empresa, entrega, filial_atual, tipo, modelo, colaborador, 
                        duplicado, status, cargo, ultimo_colaborador, multi_usuario, observacao, 
                        service_tag_monitor, cc, cc_contab, desc_cc_contab, emp_colab, filial_colab, 
                        filial_rh_corrigido, coluna2, cc_dif, filial_dif, nf_transf, filial_dest_transf, 
                        order_sale, remessa, contrato, patrimonio, envio_dell, fim_garantia, 
                        reportado_inventario, usuario_inventario, memoria, memoria_adicional, 
                        localizacao, troca_chg_2_leva_2025, x
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                `, [
                    String(tag).trim().toUpperCase(), row['empresa'] || row['emp'], row['entrega'], row['filial atual'] || row['filial'],
                    row['tipo'], row['modelo'], row['colaborador'] || row['colaborador atual'], row['duplicado?'] || row['duplicado'],
                    row['status'], row['cargo'], row['último colaborador'] || row['ultimo colaborador'],
                    row['multi usuário?'] || row['multi usuario?'] || row['multi_usuario'], row['observação'] || row['observacao'],
                    row['service tag monitor'], row['cc'], row['cc contab'], row['desc cc contab'] || row['cc desc colab'] || row['cc dsc cont'],
                    row['emp colab'] || row['empresa colab'], row['filial colab'], row['filial rh corrigido'], row['coluna2'],
                    row['cc dif'] || row['cc diferente'], row['filial dif'] || row['filial diferente'], row['nf transf'], row['filial dest transf'],
                    row['order sale'], row['remessa'], row['contrato'], row['patrimônio'] || row['patrimonio'], row['envio dell'], row['fim_garantia'],
                    row['reportado inventário'] || row['reportado inventario'], row['usuário inventário'] || row['usuario inventario'],
                    row['memória'] || row['memoria'], row['mamória adicional'] || row['memória adicional'], row['localização'] || row['localizacao'],
                    row['troca chg - 2 leva - 2025'] || row['troca chg 2 leva 2025'], row['x']
                ]);
                sucesso++;
            } catch(e) { falhas++; }
        }
        fs.unlinkSync(req.file.path);
        res.json({ sucesso, falhas });
    } catch (err) { 
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path); 
        res.status(500).json({ error: err.message }); 
    }
});

// ==========================================================================
// COMPRAS TI
// ==========================================================================
app.post('/api/compras', async (req, res) => {
    try {
        const { chamado, quantidade, equipamentos, filial, setor, beneficiado } = req.body;
        const emailSolicitante = req.usuarioLogado.email.toLowerCase().trim();
        const dataHoje = new Date().toISOString().split('T')[0];

        if (!equipamentos || !filial || !quantidade) {
            return res.status(400).json({ error: 'Os campos Equipamento, Filial e Quantidade são obrigatórios.' });
        }

        await db.run(`
            INSERT INTO solicitacoes_compras (
                data_solicitacao, solicitante_email, chamado, quantidade, 
                equipamentos, filial, setor, beneficiado, status_gerente, status_logistica
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDENTE', 'Aguardando Aprovação')
        `, [dataHoje, emailSolicitante, chamado || '', quantidade, equipamentos, filial, setor || '', beneficiado || '']);

        res.status(201).json({ mensagem: 'Solicitação de compra registrada com sucesso!' });
    } catch (e) { 
        console.error('Erro ao salvar compra:', e);
        res.status(500).json({ error: 'Erro interno ao salvar solicitação: ' + e.message }); 
    }
});

app.get('/api/compras', async (req, res) => {
    try {
        const compras = await db.all('SELECT * FROM solicitacoes_compras ORDER BY id DESC');
        res.json(compras);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/compras/:id/autorizacao', async (req, res) => {
    if (!req.usuarioLogado.isAdmin) {
        return res.status(403).json({ error: 'Acesso negado. Apenas o Gerente de TI pode aprovar ou reprovar solicitações.' });
    }
    try {
        const { id } = req.params;
        const { novaDecisao } = req.body;

        if (!['APROVADO', 'REPROVADO'].includes(novaDecisao)) {
            return res.status(400).json({ error: 'Decisão inválida.' });
        }
        const novoStatusLogistica = novaDecisao === 'APROVADO' ? 'Em Cotação' : 'Recusado pelo Gerente';

        const resultado = await db.run(`
            UPDATE solicitacoes_compras 
            SET status_gerente = ?, status_logistica = ? 
            WHERE id = ?
        `, [novaDecisao, novoStatusLogistica, id]);

        if (resultado.changes === 0) return res.status(404).json({ error: 'Solicitação não encontrada.' });
        res.json({ mensagem: `Pedido updated para ${novaDecisao} com sucesso!` });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/compras/:id/logistica', async (req, res) => {
    try {
        const { id } = req.params;
        const { status_logistica, data_envio_instalacao, numero_oc } = req.body;

        const pedidoAtual = await db.get('SELECT status_gerente FROM solicitacoes_compras WHERE id = ?', [id]);
        if (!pedidoAtual) return res.status(404).json({ error: 'Solicitação não encontrada.' });

        if (pedidoAtual.status_gerente !== 'APROVADO') {
            return res.status(400).json({ error: 'Não é possível atualizar a logística de um pedido que não está APROVADO pelo Gerente.' });
        }

        await db.run(`
            UPDATE solicitacoes_compras 
            SET status_logistica = ?, data_envio_instalacao = ?, numero_oc = ? 
            WHERE id = ?
        `, [status_logistica, data_envio_instalacao, numero_oc, id]);

        res.json({ mensagem: 'Andamento da compra updated com sucesso!' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==========================================================================
// MÓDULO DE CELULARES
// ==========================================================================
app.get('/api/celulares', async (req, res) => {
    try {
        const celulares = await db.all('SELECT * FROM celulares ORDER BY colaborador ASC');
        const hoje = new Date();
        const hojeZerado = new Date(hoje.getFullYear(), hoje.getMonth(), hoje.getDate());

        let totalAtivos = 0;
        let garantiasExpiradas = 0;
        let disponiveis = 0;

        const celularesCalculados = celulares.map(cel => {
            if (cel.status && cel.status.toLowerCase().includes('ativo')) totalAtivos++;
            const colab = (cel.colaborador || '').toLowerCase();
            if (colab.includes('disponivel') || colab === '') disponiveis++;

            let statusGarantia = 'Sem informação';
            let diasRestantes = 'N/A';

            if (cel.data_vencimento_garantia) {
                const dataGarantia = new Date(cel.data_vencimento_garantia + 'T12:00:00');
                if (!isNaN(dataGarantia.getTime())) {
                    const fimZerado = new Date(dataGarantia.getFullYear(), dataGarantia.getMonth(), dataGarantia.getDate());
                    const diffDias = Math.ceil((fimZerado - hojeZerado) / (1000 * 60 * 60 * 24));
                    if (diffDias <= 0) {
                        statusGarantia = '⚠️ EXPIRADA';
                        garantiasExpiradas++;
                        diasRestantes = `Expirou há ${Math.abs(diffDias)} dias`;
                    } else {
                        statusGarantia = 'Válida';
                        diasRestantes = `${diffDias} dias restantes`;
                    }
                }
            }

            return { ...cel, garantia_status_real: statusGarantia, dias_para_vencer: diasRestantes };
        });

        const distMarcas = await db.all("SELECT marca, COUNT(*) as qtd FROM celulares WHERE marca IS NOT NULL AND marca != '' GROUP BY marca ORDER BY qtd DESC");
        const distEmpresas = await db.all("SELECT emp_destino as empresa, COUNT(*) as qtd FROM celulares WHERE emp_destino IS NOT NULL AND emp_destino != '' GROUP BY emp_destino ORDER BY qtd DESC");

        res.json({
            celulares: celularesCalculados,
            total: celulares.length,
            ativos: totalAtivos,
            expiradas: garantiasExpiradas,
            disponiveis: disponiveis,
            graficoMarcas: distMarcas,
            graficoEmpresas: distEmpresas
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/celulares', async (req, res) => {
    if (!req.usuarioLogado.isAdmin) return res.status(403).json({ error: 'Apenas administradores.' });
    const d = req.body;
    if (!d.imei || !String(d.imei).trim()) return res.status(400).json({ error: 'IMEI obrigatório.' });

    try {
        await db.run(`INSERT INTO celulares (
            imei, modelo, marca, numero_linha, colaborador, status,
            emp_destino, filial_destino, assinou_termo, mu, fone, carregador,
            cabo, obs, conforme_orcamento, coluna1, data_entrega,
            data_vencimento_garantia, patrimonio
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, [
            d.imei.trim().toUpperCase(), d.modelo, d.marca, d.numero_linha, d.colaborador,
            d.status || 'Ativo', d.emp_destino, d.filial_destino, d.assinou_termo,
            d.mu, d.fone, d.carregador, d.cabo, d.obs, d.conforme_orcamento,
            d.coluna1, d.data_entrega, d.data_vencimento_garantia, d.patrimonio
        ]);
        res.status(201).json({ mensagem: 'Celular cadastrado!' });
    } catch (e) { res.status(500).json({ error: 'IMEI duplicado ou erro: ' + e.message }); }
});

app.put('/api/celulares/:imei', async (req, res) => {
    if (!req.usuarioLogado.isAdmin) return res.status(403).json({ error: 'Apenas administradores.' });
    const { imei } = req.params;
    const d = req.body;
    const chave = String(imei).trim().toUpperCase();

    try {
        const r = await db.run(`UPDATE celulares SET
            modelo=?, marca=?, numero_linha=?, colaborador=?, status=?,
            emp_destino=?, filial_destino=?, assinou_termo=?, mu=?, fone=?,
            carregador=?, cabo=?, obs=?, conforme_orcamento=?, coluna1=?,
            data_entrega=?, data_vencimento_garantia=?, patrimonio=?,
            updated_at=CURRENT_TIMESTAMP WHERE imei=?`, [
            d.modelo, d.marca, d.numero_linha, d.colaborador, d.status,
            d.emp_destino, d.filial_destino, d.assinou_termo, d.mu, d.fone,
            d.carregador, d.cabo, d.obs, d.conforme_orcamento, d.coluna1,
            d.data_entrega, d.data_vencimento_garantia, d.patrimonio, chave
        ]);
        if (r.changes === 0) return res.status(404).json({ error: 'Celular não encontrado.' });
        res.json({ mensagem: 'Celular atualizado!' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/celulares/:imei', async (req, res) => {
    if (!req.usuarioLogado.isAdmin) return res.status(403).json({ error: 'Apenas administradores.' });
    try {
        const r = await db.run('DELETE FROM celulares WHERE imei = ?', [req.params.imei]);
        if (r.changes === 0) return res.status(404).json({ error: 'Celular não encontrado.' });
        res.json({ mensagem: 'Celular removido.' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/celulares/importar', upload.single('planilha'), async (req, res) => {
    if (!req.usuarioLogado.isAdmin) {
        if (req.file) fs.unlinkSync(req.file.path);
        return res.status(403).json({ error: 'Apenas administradores.' });
    }
    if (!req.file) return res.status(400).json({ error: 'Arquivo ausente.' });

    try {
        const wb = xlsx.readFile(req.file.path, { codepage: 65001 });
        const sheet = wb.SheetNames.includes('Celulares') ? 'Celulares' : wb.SheetNames[0];
        const dados = xlsx.utils.sheet_to_json(wb.Sheets[sheet]);
        let suc = 0, fal = 0;

        for (let raw of dados) {
            const row = {};
            Object.keys(raw).forEach(k => { row[k.replace(/\r?\n/g, ' ').trim().toLowerCase()] = raw[k]; });
            const imei = row['imei'] || row['imei 1'] || row['imei1'];
            if (!imei || String(imei).trim() === '' || String(imei).toLowerCase().includes('imei')) continue;

            try {
                await db.run(`INSERT INTO celulares (
                    imei, modelo, marca, numero_linha, colaborador, status,
                    emp_destino, filial_destino, assinou_termo, mu, fone, carregador,
                    cabo, obs, conforme_orcamento, coluna1, data_entrega,
                    data_vencimento_garantia, patrimonio
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, [
                    String(imei).trim().toUpperCase(),
                    row['modelo'], row['marca'], row['número'] || row['numero'] || row['linha'],
                    row['colaborador'] || row['usuário'] || row['usuario'],
                    row['status'] || 'Ativo', row['emp destino'] || row['emp_destino'],
                    row['filial destino'] || row['filial_destino'],
                    row['assinou termo?'] || row['assinou_termo'],
                    row['mu?'] || row['mu'], row['fone'], row['carregador'],
                    row['cabo'], row['obs'], row['conforme orçamento?'] || row['conforme_orcamento'],
                    row['coluna1'], row['data entrega'] || row['data_entrega'],
                    row['vencimento garantia'] || row['data_vencimento_garantia'],
                    row['patrimônio'] || row['patrimonio']
                ]);
                suc++;
            } catch (e) { fal++; }
        }
        fs.unlinkSync(req.file.path);
        res.json({ sucesso: suc, falhas: fal });
    } catch (e) {
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        res.status(500).json({ error: e.message });
    }
});