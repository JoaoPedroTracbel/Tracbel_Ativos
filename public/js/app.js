/**
 * @file app.js
 * @description Controladora front-end do inventário Tracbel com suporte a tratamento anti-XSS, Módulo de Compras corrigido, Dashboard Gráfico, Máscaras, Dropdown de Colunas, Módulo de Celulares e Logout funcional.
 * @author TI Tracbel
 */

document.addEventListener('DOMContentLoaded', () => {
    let todosAtivos = [];
    let ativosFiltrados = [];
    let todasCompras = [];
    let colunaOrdenada = '';
    let ordemAscendente = true;
    let usuarioLogadoSistema = null;
    let instanciaGraficoEmpresas = null;

    // Módulo de celulares
    let todosCelulares = [];
    let celularesFiltrados = [];
    let graficoMarcasCelulares = null;
    let graficoEmpresasCelulares = null;

    const DICIONARIO_COLUNAS = {
        service_tag: "Service Tag", empresa: "Empresa", entrega: "Entrega", filial_atual: "Filial Atual",
        tipo: "Tipo", modelo: "Modelo", colaborador: "Colaborador", duplicado: "Duplicado?",
        status: "Status", cargo: "Cargo", ultimo_colaborador: "Último Colab", multi_usuario: "Multi Usuário?",
        observacao: "Observação", service_tag_monitor: "ST Monitor", cc: "CC", cc_contab: "CC Contab",
        desc_cc_contab: "Desc CC Contab", emp_colab: "Emp Colab", filial_colab: "Filial Colab",
        filial_rh_corrigido: "Filial RH Corrigido", coluna2: "Coluna2", cc_dif: "CC DIF",
        filial_dif: "FILIAL DIF", nf_transf: "NF Transf", filial_dest_transf: "Filial Dest Transf",
        order_sale: "Order Sale", remessa: "Remessa", contrato: "Contrato", patrimonio: "Patrimônio",
        envio_dell: "Envio Dell", fim_garantia: "Fim Garantia", dias_para_vencer: "Dias p/ Vencer",
        tempo_computador: "Tempo Computador", tempo_garantia: "Tempo Garantia",
        reportado_inventario: "Reportado Inv", usuario_inventario: "Usuário Inv",
        memoria: "Memória", memoria_adicional: "Memória Adicional", localizacao: "Localização",
        troca_chg_2_leva_2025: "Troca CHG 2025", x: "X"
    };

    const tabelaCorpo = document.getElementById('ativos-corpo');
    const inputBusca = document.getElementById('search-input');
    const filtroColuna = document.getElementById('filtro-coluna');
    const formCadastroManual = document.getElementById('form-cadastro-manual');
    const formCompra = document.getElementById('form-solicitar-compra');
    const tabelaComprasCorpo = document.getElementById('compras-corpo');
    const filtroMesCompras = document.getElementById('filtro-compras-mes');
    const buscaComprasInput = document.getElementById('search-compras-input');

    const TEMPO_MAXIMO_INATIVO = 30 * 60 * 1000;

    function resetarTimerInatividade() {
        localStorage.setItem('ultimoAcessoAtivo', Date.now());
    }

    function verificarInatividadeSessao() {
        const ultimoAcesso = localStorage.getItem('ultimoAcessoAtivo');
        if (ultimoAcesso) {
            const tempoPassado = Date.now() - Number(ultimoAcesso);
            if (tempoPassado >= TEMPO_MAXIMO_INATIVO) {
                localStorage.removeItem('firebaseToken');
                localStorage.removeItem('ultimoAcessoAtivo');
                localStorage.removeItem('servidorInstanciaId');
                alert("⚠️ Sua sessão expirou por inatividade de 30 minutos. Faça login novamente por segurança.");
                window.location.href = '/login.html';
            }
        }
    }

    window.addEventListener('mousemove', resetarTimerInatividade);
    window.addEventListener('keypress', resetarTimerInatividade);
    window.addEventListener('click', resetarTimerInatividade);
    window.addEventListener('scroll', resetarTimerInatividade);
    setInterval(verificarInatividadeSessao, 10000);
    verificarInatividadeSessao();

    // LOGOUT
    document.getElementById('btn-logoff').addEventListener('click', () => {
        if (confirm('Deseja realmente sair do sistema?')) {
            localStorage.removeItem('firebaseToken');
            localStorage.removeItem('servidorInstanciaId');
            localStorage.removeItem('ultimoAcessoAtivo');
            window.location.href = '/login.html';
        }
    });

    window.alterarNivelUsuario = async function(email, novaRole) {
        if (!confirm(`Deseja alterar as permissões de ${email} para ${novaRole.toUpperCase()}?`)) return;
        try {
            const resposta = await fetchProtegido('/api/usuarios/role', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: email, novaRole: novaRole })
            });
            const resultado = await resposta.json();
            if (resposta.ok) {
                alert(resultado.mensagem);
                carregarListaUsuarios();
            } else {
                alert(`Erro: ${resultado.error}`);
            }
        } catch (err) { alert('Falha ao processar alteração.'); }
    };

    window.rejeitarUsuarioRapido = async function(email) {
        if (!confirm(`Tem certeza que deseja REJEITAR a solicitação de ${email}?`)) return;
        try {
            const resposta = await fetchProtegido('/api/usuarios/rejeitar', {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: email })
            });
            const resultado = await resposta.json();
            if (resposta.ok) {
                alert(resultado.mensagem);
                carregarListaUsuarios();
            } else {
                alert(`Erro: ${resultado.error}`);
            }
        } catch (err) { alert('Falha ao processar rejeição.'); }
    };

    window.excluirUsuarioAtivo = async function(email) {
        if (!confirm(`⚠️ ATENÇÃO EXTREMA:\nDeseja REVOGAR e EXCLUIR permanentemente o acesso do usuário ${email}?\nEle será deslogado e bloqueado imediatamente!`)) return;
        try {
            const resposta = await fetchProtegido('/api/usuarios/excluir', {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: email })
            });
            const resultado = await resposta.json();
            if (resposta.ok) {
                alert(resultado.mensagem);
                carregarListaUsuarios();
            } else {
                alert(`Erro: ${resultado.error}`);
            }
        } catch (err) { alert('Erro na comunicação de rede ao revogar.'); }
    };

    function escaparHTML(stringRaw) {
        if (stringRaw === null || stringRaw === undefined) return ''; 
        return String(stringRaw)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;');
    }

    function aplicarMascaraData(input) {
        input.addEventListener('input', (e) => {
            let v = e.target.value.replace(/\D/g, '').substring(0, 8);
            if (v.length >= 5) {
                e.target.value = `${v.substring(0, 2)}/${v.substring(2, 4)}/${v.substring(4, 8)}`;
            } else if (v.length >= 3) {
                e.target.value = `${v.substring(0, 2)}/${v.substring(2, 4)}`;
            } else {
                e.target.value = v;
            }
        });
    }

    const campoEnvioDell = document.querySelector("input[name='envio_dell']");
    const campoFimGarantia = document.querySelector("input[name='fim_garantia']");
    if (campoEnvioDell) aplicarMascaraData(campoEnvioDell);
    if (campoFimGarantia) aplicarMascaraData(campoFimGarantia);

    // SUB-ABAS DE CADASTRO
    const subTabBtns = document.querySelectorAll('.sub-tab-btn');
    const formComputador = document.getElementById('form-cadastro-manual');
    const formCelular = document.getElementById('form-cadastro-celular');

    subTabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const sub = btn.dataset.sub;
            subTabBtns.forEach(b => { b.classList.remove('active'); b.style.borderBottom = '3px solid transparent'; b.style.color = '#666'; });
            btn.classList.add('active');
            btn.style.borderBottom = '3px solid var(--tracbel-yellow)';
            btn.style.color = 'var(--tracbel-dark)';

            if (sub === 'computador') {
                formComputador.style.display = '';
                formCelular.style.display = 'none';
                delete formCelular.dataset.modo;
                if (formCelular.querySelector("input[name='imei']")) formCelular.querySelector("input[name='imei']").readOnly = false;
            } else {
                formComputador.style.display = 'none';
                formCelular.style.display = '';
                delete formComputador.dataset.modo;
                if (formComputador.querySelector("input[name='service_tag']")) formComputador.querySelector("input[name='service_tag']").readOnly = false;
            }
        });
    });

    async function verificarPerfil() {
        try {
            const checaInstancia = await fetch('/api/config/instancia');
            if (checaInstancia.ok) {
                const dadosInstancia = await checaInstancia.json();
                const ultimaInstanciaSalva = localStorage.getItem('servidorInstanciaId');
                if (ultimaInstanciaSalva && ultimaInstanciaSalva !== dadosInstancia.instanciaId) {
                    localStorage.removeItem('firebaseToken');
                    localStorage.removeItem('ultimoAcessoAtivo');
                    localStorage.removeItem('servidorInstanciaId');
                    window.location.href = '/login.html';
                    return;
                }
                localStorage.setItem('servidorInstanciaId', dadosInstancia.instanciaId);
            }

            const res = await fetchProtegido('/api/auth/perfil');
            if (!res || !res.ok) throw new Error("Não foi possível obter o perfil autenticado.");
            usuarioLogadoSistema = await res.json();
            
            const displayUser = document.getElementById('user-display');
            if (displayUser) {
                displayUser.innerHTML = `<i class="fa-solid fa-user-shield"></i> ${escaparHTML(usuarioLogadoSistema.email)} (${usuarioLogadoSistema.isAdmin ? 'ADMIN' : 'LEITURA'})`;
            }
            
            if (document.getElementById('usr-email')) document.getElementById('usr-email').textContent = usuarioLogadoSistema.email;
            if (document.getElementById('usr-uid')) document.getElementById('usr-uid').textContent = usuarioLogadoSistema.uid;
            if (document.getElementById('usr-role')) {
                document.getElementById('usr-role').innerHTML = usuarioLogadoSistema.isAdmin 
                    ? `<span class="badge-valid">TI Administrador</span>` 
                    : `<span class="badge-expired" style="background:#f1f1f1; color:#666;">Acesso Comum (Leitura)</span>`;
            }

            inicializarPainelConfiguracaoColunas();

            if (!usuarioLogadoSistema.isAdmin) {
                const zone = document.querySelector('.upload-zone');
                if (zone) zone.style.display = 'none';
                const btnCad = document.querySelector("button[onclick*='cadastro']");
                if (btnCad) btnCad.style.display = 'none';
                const btnUsr = document.getElementById('btn-usuarios-aba');
                if (btnUsr) btnUsr.style.display = 'none';
                const panelGestao = document.getElementById('painel-gestao-ti');
                if (panelGestao) panelGestao.style.display = 'none';
                // esconder upload de celulares se não for admin
                const zoneCel = document.querySelector('.upload-zone-celulares');
                if (zoneCel) zoneCel.style.display = 'none';
            }
        } catch (e) { 
            console.error("Falha na validação de perfil:", e);
            window.location.href = '/login.html'; 
        }
    }

    window.alternarAba = function(aba) {
        document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
        
        const btnAlvo = document.querySelector(`button[onclick*='${aba}']`);
        if (btnAlvo) btnAlvo.classList.add('active');
        
        const painelAlvo = document.getElementById(`aba-${aba}`);
        if (painelAlvo) painelAlvo.classList.add('active');
        
        if (aba === 'lista') carregarAtivos();
        if (aba === 'usuarios') carregarListaUsuarios();
        if (aba === 'compras') carregarSolicitacoesCompras(true);
        if (aba === 'celulares') carregarCelulares();
        if (aba === 'cadastro') {
            const btnComputador = document.querySelector('.sub-tab-btn[data-sub="computador"]');
            if (btnComputador) btnComputador.click();
        }
    };

    // ===================== ATIVOS =====================
    async function carregarAtivos() {
        try {
            if (tabelaCorpo) {
                tabelaCorpo.innerHTML = `<tr><td colspan="42" class="loading-td"><i class="fa-solid fa-spinner fa-spin"></i> Atualizando Painel Analítico Tracbel...</td></tr>`;
            }
            const resposta = await fetchProtegido('/api/ativos');
            if (!resposta || !resposta.ok) throw new Error("Erro na rota de ativos.");
            
            const jsonPainel = await resposta.json();
            todosAtivos = jsonPainel.ativos || [];
            ativosFiltrados = [...todosAtivos];
            
            if (document.getElementById('total-ativos')) document.getElementById('total-ativos').textContent = jsonPainel.total || 0;
            if (document.getElementById('garantias-expiradas')) document.getElementById('garantias-expiradas').textContent = jsonPainel.expiradas || 0;
            if (document.getElementById('dispositivos-disponiveis')) document.getElementById('dispositivos-disponiveis').textContent = jsonPainel.disponiveis || 0;
            if (document.getElementById('compras-pendentes-dash')) document.getElementById('compras-pendentes-dash').textContent = jsonPainel.comprasPendentes || 0;
            if (document.getElementById('compras-mes-dash')) document.getElementById('compras-mes-dash').textContent = jsonPainel.comprasMes || 0;

            renderizarGraficoDistribuicao(jsonPainel.graficoEmpresas || []);
            executarFiltroEPesquisa();
        } catch (e) {
            console.error(e);
        }
    }

    function renderizarGraficoDistribuicao(dadosAgrupados) {
        const ctxCanvas = document.getElementById('chart-empresas');
        if (!ctxCanvas) return;
        if (instanciaGraficoEmpresas) instanciaGraficoEmpresas.destroy();
        instanciaGraficoEmpresas = new Chart(ctxCanvas, {
            type: 'doughnut',
            data: {
                labels: dadosAgrupados.map(item => item.empresa || 'Não Informada'),
                datasets: [{
                    data: dadosAgrupados.map(item => item.quantidade),
                    backgroundColor: ['#f1c40f', '#2c3e50', '#2980b9', '#2ecc71', '#e74c3c', '#9b59b6', '#1abc9c', '#e67e22', '#95a5a6', '#34495e'],
                    borderWidth: 1,
                    borderColor: '#ffffff'
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });
    }

    function executarFiltroEPesquisa() {
        const termo = inputBusca ? inputBusca.value.toLowerCase().trim() : '';
        const colunaSelecionada = filtroColuna ? filtroColuna.value : 'todos';
        ativosFiltrados = todosAtivos.filter(ativo => {
            if (!termo) return true;
            if (colunaSelecionada === "todos") {
                return Object.values(ativo).some(v => v !== null && String(v).toLowerCase().includes(termo));
            } else {
                const valorCampo = ativo[colunaSelecionada];
                return valorCampo !== null && valorCampo !== undefined && String(valorCampo).toLowerCase().includes(termo);
            }
        });
        if (colunaOrdenada) aplicarOrdenacaoLogica();
        else renderizarTabela();
    }

    if (inputBusca) inputBusca.addEventListener('input', executarFiltroEPesquisa);
    if (filtroColuna) filtroColuna.addEventListener('change', executarFiltroEPesquisa);
    if (filtroMesCompras) filtroMesCompras.addEventListener('change', () => carregarSolicitacoesCompras());
    if (buscaComprasInput) buscaComprasInput.addEventListener('input', () => carregarSolicitacoesCompras());

    window.ordenarPor = function(coluna) {
        if (colunaOrdenada === coluna) {
            ordemAscendente = !ordemAscendente;
        } else {
            colunaOrdenada = coluna;
            ordemAscendente = true;
        }
        document.querySelectorAll('th i').forEach(i => i.className = 'fa-solid fa-sort');
        const th = document.querySelector(`th[data-col-id="${coluna}"] i`);
        if (th) th.className = ordemAscendente ? 'fa-solid fa-sort-up' : 'fa-solid fa-sort-down';
        aplicarOrdenacaoLogica();
    };

    function aplicarOrdenacaoLogica() {
        ativosFiltrados.sort((a, b) => {
            let valA = a[colunaOrdenada] ? String(a[colunaOrdenada]).toLowerCase() : '';
            let valB = b[colunaOrdenada] ? String(b[colunaOrdenada]).toLowerCase() : '';
            if (!isNaN(valA) && !isNaN(valB) && valA !== '' && valB !== '') return ordemAscendente ? Number(valA) - Number(valB) : Number(valB) - Number(valA);
            return ordemAscendente ? valA.localeCompare(valB) : valB.localeCompare(valA);
        });
        renderizarTabela();
    }

    function renderizarTabela() {
        if (!tabelaCorpo) return;
        if (ativosFiltrados.length === 0) {
            tabelaCorpo.innerHTML = `<tr><td colspan="42" class="loading-td">Nenhum ativo corresponde aos critérios.</td></tr>`;
            return;
        }
        tabelaCorpo.innerHTML = ativosFiltrados.map(ativo => {
            let colaboradorTexto = ativo.colaborador ? String(ativo.colaborador).trim().toUpperCase() : '';
            let colaboradorRender = escaparHTML(ativo.colaborador);
            if (colaboradorTexto === "3. DISPONÍVEL NA FILIAL" || colaboradorTexto === "3. DISPONIVEL NA FILIAL") {
                colaboradorRender = `<span class="status-disponivel"><i class="fa-solid fa-boxes-stacked"></i> 3. DISPONÍVEL NA FILIAL</span>`;
            }
            let statusGarantiaVisual = ativo.garantia_status_real === "⚠️ EXPIRADA" ? '<br><span class="badge-expired">Expirada</span>' : '<br><span class="badge-valid">Válida</span>';
            return `
                <tr ondblclick="abrirEdicao('${escaparHTML(ativo.service_tag)}')" style="cursor:pointer;">
                    <td data-col-name="service_tag" style="font-weight:bold; color:var(--tracbel-dark);">${escaparHTML(ativo.service_tag)}</td>
                    <td data-col-name="empresa"><span class="tag-empresa">${escaparHTML(ativo.empresa)}</span></td>
                    <td data-col-name="entrega">${escaparHTML(ativo.entrega)}</td>
                    <td data-col-name="filial_atual">${escaparHTML(ativo.filial_atual)}</td>
                    <td data-col-name="tipo">${escaparHTML(ativo.tipo)}</td>
                    <td data-col-name="modelo">${escaparHTML(ativo.modelo)}</td>
                    <td data-col-name="colaborador">${colaboradorRender}</td>
                    <td data-col-name="duplicado">${escaparHTML(ativo.duplicado)}</td>
                    <td data-col-name="status">${escaparHTML(ativo.status)}</td>
                    <td data-col-name="cargo">${escaparHTML(ativo.cargo)}</td>
                    <td data-col-name="ultimo_colaborador">${escaparHTML(ativo.ultimo_colaborador)}</td>
                    <td data-col-name="multi_usuario">${escaparHTML(ativo.multi_usuario)}</td>
                    <td data-col-name="observacao">${escaparHTML(ativo.observacao)}</td>
                    <td data-col-name="service_tag_monitor">${escaparHTML(ativo.service_tag_monitor)}</td>
                    <td data-col-name="cc">${escaparHTML(ativo.cc)}</td>
                    <td data-col-name="cc_contab">${escaparHTML(ativo.cc_contab)}</td>
                    <td data-col-name="desc_cc_contab">${escaparHTML(ativo.desc_cc_contab)}</td>
                    <td data-col-name="emp_colab">${escaparHTML(ativo.emp_colab)}</td>
                    <td data-col-name="filial_colab">${escaparHTML(ativo.filial_colab)}</td>
                    <td data-col-name="filial_rh_corrigido">${escaparHTML(ativo.filial_rh_corrigido)}</td>
                    <td data-col-name="coluna2">${escaparHTML(ativo.coluna2)}</td>
                    <td data-col-name="cc_dif">${escaparHTML(ativo.cc_dif)}</td>
                    <td data-col-name="filial_dif">${escaparHTML(ativo.filial_dif)}</td>
                    <td data-col-name="nf_transf">${escaparHTML(ativo.nf_transf)}</td>
                    <td data-col-name="filial_dest_transf">${escaparHTML(ativo.filial_dest_transf)}</td>
                    <td data-col-name="order_sale">${escaparHTML(ativo.order_sale)}</td>
                    <td data-col-name="remessa">${escaparHTML(ativo.remessa)}</td>
                    <td data-col-name="contrato">${escaparHTML(ativo.contrato)}</td>
                    <td data-col-name="patrimonio">${escaparHTML(ativo.patrimonio)}</td>
                    <td data-col-name="envio_dell">${escaparHTML(ativo.envio_dell)}</td>
                    <td data-col-name="fim_garantia">${escaparHTML(ativo.fim_garantia)} ${statusGarantiaVisual}</td>
                    <td data-col-name="dias_para_vencer" style="font-weight:bold; color:#2c3e50;">${escaparHTML(ativo.dias_para_vencer)}</td>
                    <td data-col-name="tempo_computador">${escaparHTML(ativo.tempo_computador)}</td>
                    <td data-col-name="tempo_garantia">${escaparHTML(ativo.tempo_garantia)}</td>
                    <td data-col-name="reportado_inventario">${escaparHTML(ativo.reportado_inventario)}</td>
                    <td data-col-name="usuario_inventario">${escaparHTML(ativo.usuario_inventario)}</td>
                    <td data-col-name="memoria">${escaparHTML(ativo.memoria)}</td>
                    <td data-col-name="memoria_adicional">${escaparHTML(ativo.memoria_adicional)}</td>
                    <td data-col-name="localizacao">${escaparHTML(ativo.localizacao)}</td>
                    <td data-col-name="troca_chg_2_leva_2025">${escaparHTML(ativo.troca_chg_2_leva_2025)}</td>
                    <td data-col-name="x">${escaparHTML(ativo.x)}</td>
                </tr>
            `;
        }).join('');
        aplicarPreferenciasDeColunasDoUsuario();
    }

    window.abrirEdicao = function(serviceTag) {
        if (!usuarioLogadoSistema || !usuarioLogadoSistema.isAdmin) { alert("Permissão de leitura apenas. Edições bloqueadas!"); return; }
        const ativo = todosAtivos.find(a => a.service_tag === serviceTag);
        if (!ativo) return;
        alternarAba('cadastro');
        document.querySelector('.sub-tab-btn[data-sub="computador"]').click();
        document.querySelector('.form-container h3').innerHTML = `<i class="fa-solid fa-edit"></i> Editando Ativo: ${escaparHTML(serviceTag)}`;
        const inputs = formCadastroManual.querySelectorAll('input');
        inputs.forEach(input => {
            if (ativo[input.name] !== undefined) input.value = ativo[input.name] || '';
        });
        formCadastroManual.querySelector("input[name='service_tag']").readOnly = true;
        formCadastroManual.dataset.modo = "edicao";
        formCadastroManual.dataset.tagOriginal = serviceTag;
    };

    if (formCadastroManual) {
        formCadastroManual.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(formCadastroManual);
            const objetoDados = Object.fromEntries(formData.entries());
            const modo = formCadastroManual.dataset.modo;
            const url = modo === "edicao" ? `/api/ativos/${formCadastroManual.dataset.tagOriginal}` : '/api/ativos';
            const metodo = modo === "edicao" ? "PUT" : "POST";
            try {
                const resposta = await fetchProtegido(url, { method: metodo, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(objetoDados) });
                if (resposta.ok) {
                    alert('Operação concluída!');
                    formCadastroManual.reset();
                    formCadastroManual.querySelector("input[name='service_tag']").readOnly = false;
                    delete formCadastroManual.dataset.modo;
                    alternarAba('lista');
                } else {
                    const r = await resposta.json(); alert(`Erro: ${r.error}`);
                }
            } catch (err) { alert('Falha ao processar formulário.'); }
        });
    }

    const fileInput = document.getElementById('file-input');
    if (fileInput) {
        fileInput.addEventListener('change', async (e) => {
            const arquivo = e.target.files[0];
            if (!arquivo) return;
            const formData = new FormData();
            formData.append('planilha', arquivo);
            try {
                const resposta = await fetchProtegido('/api/ativos/importar', { method: 'POST', body: formData });
                const r = await resposta.json();
                alert(`Lote processado!\nRegistros adicionados: ${r.sucesso}\nFalhas: ${r.falhas}`);
                carregarAtivos();
            } catch (err) { alert('Erro na importação.'); }
        });
    }

    // ===================== CELULARES =====================
    async function carregarCelulares() {
        const tabela = document.getElementById('celulares-corpo');
        if (!tabela) return;
        tabela.innerHTML = `<tr><td colspan="15" class="loading-td"><i class="fa-solid fa-spinner fa-spin"></i> Carregando celulares...</td></tr>`;
        try {
            const resp = await fetchProtegido('/api/celulares');
            if (!resp || !resp.ok) throw new Error('Erro ao carregar celulares.');
            const json = await resp.json();
            todosCelulares = json.celulares || [];
            celularesFiltrados = [...todosCelulares];

            document.getElementById('total-celulares').textContent = json.total || 0;
            document.getElementById('celulares-expiradas').textContent = json.expiradas || 0;
            document.getElementById('celulares-disponiveis').textContent = json.disponiveis || 0;
            document.getElementById('celulares-ativos').textContent = json.ativos || 0;

            renderizarGraficoMarcasCelulares(json.graficoMarcas || []);
            renderizarGraficoEmpresasCelulares(json.graficoEmpresas || []);
            aplicarFiltroCelulares();
        } catch (e) {
            console.error(e);
            tabela.innerHTML = `<tr><td colspan="15" class="loading-td" style="color:red;">Erro ao carregar.</td></tr>`;
        }
    }

    function renderizarGraficoMarcasCelulares(dados) {
        const ctx = document.getElementById('chart-marcas-celulares');
        if (!ctx) return;
        if (graficoMarcasCelulares) graficoMarcasCelulares.destroy();
        graficoMarcasCelulares = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: dados.map(d => d.marca || 'Sem marca'),
                datasets: [{ data: dados.map(d => d.qtd), backgroundColor: ['#f39c12','#e74c3c','#2980b9','#2ecc71','#9b59b6','#1abc9c'] }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });
    }

    function renderizarGraficoEmpresasCelulares(dados) {
        const ctx = document.getElementById('chart-empresas-celulares');
        if (!ctx) return;
        if (graficoEmpresasCelulares) graficoEmpresasCelulares.destroy();
        graficoEmpresasCelulares = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: dados.map(d => d.empresa || 'Não informada'),
                datasets: [{ data: dados.map(d => d.qtd), backgroundColor: ['#f1c40f','#2c3e50','#2980b9','#2ecc71','#e74c3c'] }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });
    }

    function aplicarFiltroCelulares() {
        const termo = document.getElementById('search-celulares-input')?.value.toLowerCase().trim() || '';
        const coluna = document.getElementById('filtro-coluna-celulares')?.value || 'todos';
        celularesFiltrados = todosCelulares.filter(cel => {
            if (!termo) return true;
            if (coluna === 'todos') return Object.values(cel).some(v => v && String(v).toLowerCase().includes(termo));
            return cel[coluna] && String(cel[coluna]).toLowerCase().includes(termo);
        });
        renderizarTabelaCelulares();
    }

    function renderizarTabelaCelulares() {
        const tbody = document.getElementById('celulares-corpo');
        if (!tbody) return;
        if (celularesFiltrados.length === 0) {
            tbody.innerHTML = `<tr><td colspan="15" class="loading-td">Nenhum celular encontrado.</td></tr>`;
            return;
        }
        tbody.innerHTML = celularesFiltrados.map(cel => `
            <tr ondblclick="editarCelular('${escaparHTML(cel.imei)}')" style="cursor:pointer;">
                <td style="font-weight:bold;">${escaparHTML(cel.imei)}</td>
                <td>${escaparHTML(cel.modelo || '-')}</td>
                <td>${escaparHTML(cel.marca || '-')}</td>
                <td>${escaparHTML(cel.numero_linha || '-')}</td>
                <td>${escaparHTML(cel.colaborador || '-')}</td>
                <td>${escaparHTML(cel.emp_destino || '-')}</td>
                <td>${escaparHTML(cel.filial_destino || '-')}</td>
                <td>${escaparHTML(cel.assinou_termo || '-')}</td>
                <td>${escaparHTML(cel.fone || '-')}</td>
                <td>${escaparHTML(cel.carregador || '-')}</td>
                <td>${escaparHTML(cel.cabo || '-')}</td>
                <td>${escaparHTML(cel.obs || '-')}</td>
                <td>${escaparHTML(cel.conforme_orcamento || '-')}</td>
                <td><span class="${cel.status==='Ativo'?'badge-valid':'badge-expired'}">${escaparHTML(cel.status)}</span></td>
                <td><button onclick="event.stopPropagation(); excluirCelular('${escaparHTML(cel.imei)}')" style="background:#e74c3c;color:#fff;border:none;padding:4px 8px;border-radius:4px;"><i class="fa-solid fa-trash"></i></button></td>
            </tr>`).join('');
    }

    window.editarCelular = function(imei) {
        if (!usuarioLogadoSistema?.isAdmin) { alert('Apenas administradores podem editar.'); return; }
        const cel = todosCelulares.find(c => c.imei === imei);
        if (!cel) return;
        alternarAba('cadastro');
        document.querySelector('.sub-tab-btn[data-sub="celular"]').click();
        document.querySelector('.form-container h3').innerHTML = `<i class="fa-solid fa-edit"></i> Editando Celular: ${escaparHTML(imei)}`;
        const form = document.getElementById('form-cadastro-celular');
        form.querySelectorAll('input, select, textarea').forEach(el => {
            if (cel[el.name] !== undefined) el.value = cel[el.name] || '';
        });
        form.querySelector("input[name='imei']").readOnly = true;
        form.dataset.modo = 'edicao';
        form.dataset.imeiOriginal = imei;
    };

    window.excluirCelular = async function(imei) {
        if (!usuarioLogadoSistema?.isAdmin) { alert('Apenas administradores.'); return; }
        if (!confirm(`Excluir celular IMEI ${imei}?`)) return;
        const resp = await fetchProtegido(`/api/celulares/${imei}`, { method: 'DELETE' });
        if (resp.ok) { alert('Removido!'); carregarCelulares(); }
        else { const e = await resp.json(); alert('Erro: ' + e.error); }
    };

    document.getElementById('search-celulares-input')?.addEventListener('input', aplicarFiltroCelulares);
    document.getElementById('filtro-coluna-celulares')?.addEventListener('change', aplicarFiltroCelulares);

    // Upload de planilha de celulares
    const fileInputCelulares = document.getElementById('file-input-celulares');
    if (fileInputCelulares) {
        fileInputCelulares.addEventListener('change', async (e) => {
            const arquivo = e.target.files[0];
            if (!arquivo) return;
            const formData = new FormData();
            formData.append('planilha', arquivo);
            try {
                const resposta = await fetchProtegido('/api/celulares/importar', { method: 'POST', body: formData });
                const r = await resposta.json();
                alert(`Lote processado!\nRegistros adicionados: ${r.sucesso}\nFalhas: ${r.falhas}`);
                carregarCelulares();
                document.getElementById('file-name-celulares').textContent = arquivo.name;
            } catch (err) { alert('Erro na importação.'); }
        });
    }

    // Formulário de celular (cadastro/edição)
    if (formCelular) {
        formCelular.addEventListener('submit', async (e) => {
            e.preventDefault();
            const data = Object.fromEntries(new FormData(formCelular).entries());
            const modo = formCelular.dataset.modo;
            const url = modo === 'edicao' ? `/api/celulares/${formCelular.dataset.imeiOriginal}` : '/api/celulares';
            const method = modo === 'edicao' ? 'PUT' : 'POST';
            try {
                const resp = await fetchProtegido(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
                if (resp.ok) {
                    alert('Salvo com sucesso!');
                    formCelular.reset();
                    formCelular.querySelector("input[name='imei']").readOnly = false;
                    delete formCelular.dataset.modo;
                    alternarAba('celulares');
                    carregarCelulares();
                } else {
                    const err = await resp.json();
                    alert('Erro: ' + err.error);
                }
            } catch (ex) { alert('Falha na comunicação.'); }
        });
    }

    // ===================== COMPRAS =====================
    async function carregarListaUsuarios() {
        const tabelaUsuarios = document.getElementById('usuarios-lista-corpo');
        if (!tabelaUsuarios) return;
        try {
            const resposta = await fetchProtegido('/api/usuarios');
            if (!resposta.ok) throw new Error("Erro de conexão");
            const lista = await resposta.json();
            if (lista.length === 0) {
                tabelaUsuarios.innerHTML = `<tr><td colspan="2" class="loading-td">Nenhum privilégio customizado ativo.</td></tr>`;
                return;
            }
            tabelaUsuarios.innerHTML = lista.map(usr => {
                let badgeRole = '';
                if (usr.role === 'admin') {
                    badgeRole = `<div style="display:flex; align-items:center; gap:8px;"><span class="badge-valid"><i class="fa-solid fa-star"></i> TI Administrador</span><button onclick="alterarNivelUsuario('${escaparHTML(usr.email)}', 'user')" class="btn-primary" style="background:#7f8c8d; padding:4px 8px; font-size:0.75rem; border:none; border-radius:4px; color:white; cursor:pointer;"><i class="fa-solid fa-angles-down"></i> Rebaixar</button><button onclick="excluirUsuarioAtivo('${escaparHTML(usr.email)}')" class="btn-logout" style="background:#e74c3c; padding:4px 8px; font-size:0.75rem; margin:0; border:none; border-radius:4px; color:white; cursor:pointer;"><i class="fa-solid fa-trash-can"></i> Revogar</button></div>`;
                } else if (usr.role === 'user') {
                    badgeRole = `<div style="display:flex; align-items:center; gap:8px;"><span class="badge-expired" style="background:#ECEFF1; color:#546E7A;"><i class="fa-solid fa-eye"></i> Acesso Comum (Leitura)</span><button onclick="alterarNivelUsuario('${escaparHTML(usr.email)}', 'admin')" class="btn-primary" style="background:#2980b9; padding:4px 8px; font-size:0.75rem; border:none; border-radius:4px; color:white; cursor:pointer;"><i class="fa-solid fa-angles-up"></i> Promover</button><button onclick="excluirUsuarioAtivo('${escaparHTML(usr.email)}')" class="btn-logout" style="background:#e74c3c; padding:4px 8px; font-size:0.75rem; margin:0; border:none; border-radius:4px; color:white; cursor:pointer;"><i class="fa-solid fa-trash-can"></i> Revogar</button></div>`;
                } else if (usr.role === 'pendente') {
                    badgeRole = `<div style="display:flex; align-items:center; gap:8px;"><span class="badge-expired" style="background:#f39c12; color:white; padding:3px 8px;"><i class="fa-solid fa-clock"></i> AGUARDANDO LIBERAÇÃO</span><button onclick="alterarNivelUsuario('${escaparHTML(usr.email)}', 'user')" class="btn-primary" style="background:#2ecc71; padding:4px 8px; font-size:0.75rem; border:none; border-radius:4px; color:white; font-weight:bold; cursor:pointer;"><i class="fa-solid fa-user-check"></i> Aprovar Leitura</button><button onclick="alterarNivelUsuario('${escaparHTML(usr.email)}', 'admin')" class="btn-primary" style="background:#2980b9; padding:4px 8px; font-size:0.75rem; border:none; border-radius:4px; color:white; font-weight:bold; cursor:pointer;"><i class="fa-solid fa-user-shield"></i> Aprovar Admin</button><button onclick="rejeitarUsuarioRapido('${escaparHTML(usr.email)}')" class="btn-logout" style="background:#e74c3c; padding:4px 8px; font-size:0.75rem; margin:0; border:none; border-radius:4px; color:white; cursor:pointer;"><i class="fa-solid fa-user-xmark"></i> Rejeitar</button></div>`;
                }
                return `<tr><td style="font-weight:600; color:#37474F;">${escaparHTML(usr.email)}</td><td>${badgeRole}</td></tr>`;
            }).join('');
        } catch (err) {
            console.error(err);
            tabelaUsuarios.innerHTML = `<tr><td colspan="2" class="loading-td" style="color:red;">Não foi possível carregar os usuários do banco.</td></tr>`;
        }
    }

    const btnSalvarPermissao = document.getElementById('btn-salvar-permissao');
    if (btnSalvarPermissao) {
        btnSalvarPermissao.addEventListener('click', async () => {
            const emailInput = document.getElementById('gestao-email').value.trim();
            const roleSelecionada = document.getElementById('gestao-role').value;
            if (!emailInput || !emailInput.includes('@')) {
                alert('Por favor, informe um e-mail corporativo válido da Tracbel.');
                return;
            }
            try {
                btnSalvarPermissao.disabled = true;
                const resposta = await fetchProtegido('/api/usuarios/role', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: emailInput, novaRole: roleSelecionada })
                });
                const resultado = await resposta.json();
                if (resposta.ok) {
                    alert(resultado.mensagem);
                    document.getElementById('gestao-email').value = ''; 
                    carregarListaUsuarios();
                } else {
                    alert(`Erro: ${resultado.error}`);
                }
            } catch (err) {
                alert('Falha na comunicação de rede.');
            } finally {
                btnSalvarPermissao.disabled = false;
            }
        });
    }

    async function carregarSolicitacoesCompras(forcarRecarga = false) {
        if (!tabelaComprasCorpo) return;
        try {
            if (todasCompras.length === 0 || forcarRecarga) {
                tabelaComprasCorpo.innerHTML = `<tr><td colspan="13" class="loading-td"><i class="fa-solid fa-spinner fa-spin"></i> Sincronizando com o Banco...</td></tr>`;
                const resposta = await fetchProtegido('/api/compras');
                if (!resposta || !resposta.ok) throw new Error("Falha ao ler requisições.");
                todasCompras = await resposta.json();
            }

            const badgeElement = document.getElementById('compras-badge');
            const pedidosPendentes = todasCompras.filter(item => item && item.status_gerente === 'PENDENTE').length;
            if (badgeElement) {
                if (pedidosPendentes > 0) { badgeElement.textContent = pedidosPendentes; badgeElement.style.display = 'inline-block'; }
                else { badgeElement.style.display = 'none'; }
            }

            const mesSelecionado = filtroMesCompras ? filtroMesCompras.value : 'todos';
            const termoBusca = buscaComprasInput ? buscaComprasInput.value.toLowerCase().trim() : '';

            let comprasFiltradas = todasCompras.filter(item => {
                if (!item) return false;
                let bMes = true;
                if (mesSelecionado !== 'todos' && item.data_solicitacao && item.data_solicitacao.includes('-')) {
                    bMes = (item.data_solicitacao.split('-')[1] === mesSelecionado);
                }
                let bTxt = true;
                if (termoBusca) {
                    bTxt = (String(item.equipamentos || '').toLowerCase().includes(termoBusca) || 
                            String(item.filial || '').toLowerCase().includes(termoBusca) || 
                            String(item.chamado || '').toLowerCase().includes(termoBusca));
                }
                return bMes && bTxt;
            });

            if (comprasFiltradas.length === 0) {
                tabelaComprasCorpo.innerHTML = `<tr><td colspan="13" class="loading-td">Nenhuma solicitação de compra cadastrada.</td></tr>`;
                return;
            }

            tabelaComprasCorpo.innerHTML = comprasFiltradas.map(item => {
                let badgeGerente = item.status_gerente === 'APROVADO' ? 'badge-valid' : 'badge-expired'; 
                if(item.status_gerente === 'PENDENTE') badgeGerente = 'badge-expired';
                let acoesGerente = '';
                if (usuarioLogadoSistema && usuarioLogadoSistema.isAdmin) {
                    if (item.status_gerente === 'PENDENTE') {
                        acoesGerente = `<td style="text-align:center;"><button onclick="decidirCompra(${item.id}, 'APROVADO')" class="btn-primary" style="background:#2ecc71; padding:4px 8px; font-size:0.75rem; border:none; border-radius:4px; color:white; cursor:pointer; margin:2px;"><i class="fa-solid fa-check"></i> Aprovar</button><button onclick="decidirCompra(${item.id}, 'REPROVADO')" class="btn-logout" style="background:#e74c3c; padding:4px 8px; font-size:0.75rem; margin:2px; border:none; border-radius:4px; color:white; cursor:pointer;"><i class="fa-solid fa-xmark"></i> Reprovar</button></td>`;
                    } else {
                        acoesGerente = `<td style="text-align:center;"><span style="font-size:0.8rem; color:#666;">${item.status_gerente}</span></td>`;
                    }
                }
                return `<tr>
                    <td>#${item.id}</td>
                    <td>${escaparHTML(item.data_solicitacao)}</td>
                    <td>${escaparHTML(item.chamado || '-')}</td>
                    <td style="text-align:center; font-weight:bold;">${item.quantidade || 1}</td>
                    <td style="font-weight:600;">${escaparHTML(item.equipamentos)}</td>
                    <td><span class="tag-empresa" style="background:#eef2f5; color:#333;">${escaparHTML(item.filial)}</span></td>
                    <td>${escaparHTML(item.setor || '-')}</td>
                    <td>${escaparHTML(item.beneficiado || '-')}</td>
                    <td><span class="${badgeGerente}">${item.status_gerente}</span></td>
                    <td>${escaparHTML(item.status_logistica || 'Aguardando')}</td>
                    <td>${escaparHTML(item.data_envio_instalacao || '-')}</td>
                    <td>${escaparHTML(item.numero_oc || '-')}</td>
                    ${acoesGerente}
                </tr>`;
            }).join('');
        } catch (err) { 
            console.error(err); 
            tabelaComprasCorpo.innerHTML = `<tr><td colspan="13" class="loading-td" style="color:red;">Falha ao carregar requisições.</td></tr>`;
        }
    }

    if (formCompra) {
        formCompra.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btnSubmitCompra = formCompra.querySelector('button[type="submit"]');
            const dadosPedido = {
                equipamentos: document.getElementById('compra-equipamento').value.trim(),
                quantidade: parseInt(document.getElementById('compra-quantidade').value),
                filial: document.getElementById('compra-filial').value.trim(),
                setor: document.getElementById('compra-setor').value.trim(),
                beneficiado: document.getElementById('compra-beneficiado').value.trim(),
                chamado: document.getElementById('compra-chamado').value.trim()
            };
            try {
                btnSubmitCompra.disabled = true;
                const resposta = await fetchProtegido('/api/compras', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(dadosPedido) });
                const resultado = await resposta.json();
                if (resposta.ok) {
                    alert('🚀 Solicitação enviada com sucesso!');
                    formCompra.reset();
                    carregarSolicitacoesCompras(true); 
                    carregarAtivos(); 
                } else {
                    alert(`Erro: ${resultado.error}`);
                }
            } catch (err) { alert('Falha na comunicação.'); } 
            finally { btnSubmitCompra.disabled = false; }
        });
    }

    window.decidirCompra = async function(id, decisao) {
        if (!confirm(`Tem certeza que deseja marcar esta requisição como ${decisao}?`)) return;
        try {
            const resposta = await fetchProtegido(`/api/compras/${id}/autorizacao`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ novaDecisao: decisao }) });
            if (resposta.ok) { carregarSolicitacoesCompras(true); carregarAtivos(); }
        } catch (err) { alert('Erro ao autorizar.'); }
    };

    // ===================== DROPDOWN DE COLUNAS =====================
    const btnToggleColunas = document.getElementById('btn-toggle-colunas');
    const dropdownConteudo = document.getElementById('dropdown-colunas-conteudo');
    const buscaColunaInput = document.getElementById('busca-coluna-input');
    if (btnToggleColunas && dropdownConteudo) {
        btnToggleColunas.addEventListener('click', (e) => {
            e.stopPropagation();
            const aberto = dropdownConteudo.style.display === 'block';
            dropdownConteudo.style.display = aberto ? 'none' : 'block';
            if (!aberto && buscaColunaInput) buscaColunaInput.focus();
        });
        document.addEventListener('click', (e) => {
            if (dropdownConteudo.style.display === 'block' && !dropdownConteudo.contains(e.target) && e.target !== btnToggleColunas) {
                dropdownConteudo.style.display = 'none';
            }
        });
    }
    if (buscaColunaInput) {
        buscaColunaInput.addEventListener('input', (e) => {
            const termo = e.target.value.toLowerCase().trim();
            document.querySelectorAll('#container-config-colunas label').forEach(label => {
                label.style.display = label.textContent.toLowerCase().includes(termo) ? 'flex' : 'none';
            });
        });
    }

    function inicializarPainelConfiguracaoColunas() {
        const container = document.getElementById('container-config-colunas');
        if (!container || !usuarioLogadoSistema) return;
        const emailChave = usuarioLogadoSistema.email.toLowerCase().trim();
        const configSalva = localStorage.getItem(`colunas_ocultas_${emailChave}`);
        const colunasOcultas = configSalva ? JSON.parse(configSalva) : [];
        container.innerHTML = Object.keys(DICIONARIO_COLUNAS).map(colId => {
            const estaChecado = !colunasOcultas.includes(colId) ? 'checked' : '';
            return `<label style="font-size:0.85rem; padding:5px 0; display:flex; align-items:center; gap:8px; cursor:pointer; user-select:none; color:#333;"><input type="checkbox" data-col-target="${colId}" ${estaChecado} style="cursor:pointer;">${DICIONARIO_COLUNAS[colId]}</label>`;
        }).join('');
        container.querySelectorAll('input[type="checkbox"]').forEach(chk => {
            chk.addEventListener('change', (e) => {
                atualizarPreferenciaColunaUsuario(e.target.getAttribute('data-col-target'), e.target.checked);
            });
        });
    }

    function atualizarPreferenciaColunaUsuario(idColuna, estaVisivel) {
        if (!usuarioLogadoSistema) return;
        const emailChave = usuarioLogadoSistema.email.toLowerCase().trim();
        const configSalva = localStorage.getItem(`colunas_ocultas_${emailChave}`);
        let colunasOcultas = configSalva ? JSON.parse(configSalva) : [];
        if (estaVisivel) colunasOcultas = colunasOcultas.filter(id => id !== idColuna);
        else if (!colunasOcultas.includes(idColuna)) colunasOcultas.push(idColuna);
        localStorage.setItem(`colunas_ocultas_${emailChave}`, JSON.stringify(colunasOcultas));
        aplicarPreferenciasDeColunasDoUsuario();
    }

    function aplicarPreferenciasDeColunasDoUsuario() {
        if (!usuarioLogadoSistema) return;
        const emailChave = usuarioLogadoSistema.email.toLowerCase().trim();
        const configSalva = localStorage.getItem(`colunas_ocultas_${emailChave}`);
        const colunasOcultas = configSalva ? JSON.parse(configSalva) : [];
        document.querySelectorAll('#tabela-ativos thead th').forEach(th => {
            th.style.display = colunasOcultas.includes(th.getAttribute('data-col-id')) ? 'none' : '';
        });
        document.querySelectorAll('#tabela-ativos tbody tr').forEach(tr => {
            tr.querySelectorAll('td').forEach(td => {
                td.style.display = colunasOcultas.includes(td.getAttribute('data-col-name')) ? 'none' : '';
            });
        });
    }

    // Inicialização
    verificarPerfil();
    carregarAtivos();
});

async function fetchProtegido(url, opcoes = {}) {
    const token = localStorage.getItem('firebaseToken');
    if (!token) { window.location.href = '/login.html'; return null; }
    if (!opcoes.headers) opcoes.headers = {};
    opcoes.headers['Authorization'] = `Bearer ${token}`;
    try {
        const resposta = await fetch(url, opcoes);
        if (resposta.status === 401 || resposta.status === 403) {
            localStorage.removeItem('firebaseToken'); 
            localStorage.removeItem('servidorInstanciaId');
            window.location.href = '/login.html';
            return null;
        }
        return resposta;
    } catch(err) { return null; }
}