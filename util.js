/**
 * DJ BROWW - Utilitários Compartilhados v4.2
 * Melhorias: validação genérica, auto-máscaras, geração de contrato,
 * tratamento de quota, assinatura digital com timestamp e hash
 */

const DJ_BROWW = {
    version: '4.2',
    cryptoKey: null,

    // ===== CRIPTOGRAFIA AES =====
    cryptoAvailable: false,

    checkCrypto() {
        try {
            const isSecure = window.isSecureContext || 
                           window.location.protocol === 'https:' || 
                           window.location.hostname === 'localhost' ||
                           window.location.hostname === '127.0.0.1' ||
                           window.location.hostname.includes('github.io');
            const hasSubtle = !!(window.crypto && crypto.subtle);
            this.cryptoAvailable = isSecure && hasSubtle;
        } catch(e) {
            this.cryptoAvailable = false;
        }
        return this.cryptoAvailable;
    },

    async initCrypto() {
        this.checkCrypto();
        if (!this.cryptoAvailable) return false;
        const savedKey = localStorage.getItem('dj_brow_crypto_key');
        if (savedKey) {
            try {
                const jwk = JSON.parse(savedKey);
                this.cryptoKey = await crypto.subtle.importKey(
                    'jwk', jwk, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
                );
                return true;
            } catch(e) {
                this.cryptoKey = null;
            }
        }
        return false;
    },

    async generateKey(password) {
        if (!this.checkCrypto()) {
            throw new Error('Criptografia não disponível. Use HTTPS ou localhost.');
        }
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw', encoder.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
        );
        const key = await crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt: encoder.encode('dj_brow_salt_2026'), iterations: 100000, hash: 'SHA-256' },
            keyMaterial, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
        );
        const jwk = await crypto.subtle.exportKey('jwk', key);
        localStorage.setItem('dj_brow_crypto_key', JSON.stringify(jwk));
        this.cryptoKey = key;
        return key;
    },

    async encrypt(data) {
        if (!this.cryptoAvailable || !this.cryptoKey) return data;
        try {
            const encoder = new TextEncoder();
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                this.cryptoKey,
                encoder.encode(JSON.stringify(data))
            );
            return { iv: Array.from(iv), data: Array.from(new Uint8Array(encrypted)) };
        } catch(e) {
            return data;
        }
    },

    async decrypt(encryptedObj) {
        if (!this.cryptoAvailable || !this.cryptoKey || !encryptedObj || !encryptedObj.iv) {
            return encryptedObj;
        }
        try {
            const iv = new Uint8Array(encryptedObj.iv);
            const data = new Uint8Array(encryptedObj.data);
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                this.cryptoKey,
                data
            );
            const decoder = new TextDecoder();
            return JSON.parse(decoder.decode(decrypted));
        } catch(e) {
            return encryptedObj;
        }
    },

    // ===== VIA CEP =====
    async fetchCEP(cep) {
        const cleanCEP = cep.replace(/\D/g, '');
        if (cleanCEP.length !== 8) return null;
        try {
            const res = await fetch(`https://viacep.com.br/ws/${cleanCEP}/json/`);
            const data = await res.json();
            if (data.erro) return null;
            return data;
        } catch(e) {
            return null;
        }
    },

    maskCEP(value) {
        return value.replace(/\D/g, '').replace(/(\d{5})(\d)/, '$1-$2').substring(0, 9);
    },

    // ===== SANITIZAÇÃO XSS =====
    escapeHtml(text) {
        if (typeof text !== 'string') return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    escapeAttr(text) {
        return this.escapeHtml(text).replace(/"/g, '&quot;').replace(/'/g, '&#039;');
    },

    // ===== MÁSCARAS DE INPUT =====
    maskCPF(value) {
        return value.replace(/\D/g, '')
            .replace(/(\d{3})(\d)/, '$1.$2')
            .replace(/(\d{3})(\d)/, '$1.$2')
            .replace(/(\d{3})(\d{1,2})$/, '$1-$2')
            .substring(0, 14);
    },

    maskCNPJ(value) {
        return value.replace(/\D/g, '')
            .replace(/(\d{2})(\d)/, '$1.$2')
            .replace(/(\d{3})(\d)/, '$1.$2')
            .replace(/(\d{3})(\d)/, '$1/$2')
            .replace(/(\d{4})(\d{1,2})$/, '$1-$2')
            .substring(0, 18);
    },

    maskPhone(value) {
        const cleaned = value.replace(/\D/g, '');
        if (cleaned.length <= 10) {
            return cleaned.replace(/(\d{2})(\d)/, '($1) $2').replace(/(\d{4})(\d)/, '$1-$2');
        }
        return cleaned.replace(/(\d{2})(\d)/, '($1) $2').replace(/(\d{5})(\d)/, '$1-$2').substring(0, 15);
    },

    maskMoney(value) {
        const cleaned = value.replace(/\D/g, '');
        const num = parseInt(cleaned) / 100;
        return num.toLocaleString('pt-BR', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    },

    unmaskMoney(value) {
        return parseFloat(value.replace(/\./g, '').replace(',', '.')) || 0;
    },

    // ===== AUTO-APLICAR MÁSCARAS =====
    autoMask(input, type) {
        input.addEventListener('input', (e) => {
            const val = e.target.value;
            switch(type) {
                case 'cpf': e.target.value = this.maskCPF(val); break;
                case 'cnpj': e.target.value = this.maskCNPJ(val); break;
                case 'cpf_cnpj': 
                    const digits = val.replace(/\D/g, '');
                    e.target.value = digits.length > 11 ? this.maskCNPJ(val) : this.maskCPF(val);
                    break;
                case 'phone': e.target.value = this.maskPhone(val); break;
                case 'cep': e.target.value = this.maskCEP(val); break;
                case 'money': e.target.value = this.maskMoney(val); break;
            }
        });
    },

    // ===== VALIDAÇÃO =====
    validateCPF(cpf) {
        cpf = cpf.replace(/\D/g, '');
        if (cpf.length !== 11 || /^(.)(\1)+$/.test(cpf)) return false;
        let sum = 0, remainder;
        for (let i = 1; i <= 9; i++) sum += parseInt(cpf.substring(i-1, i)) * (11 - i);
        remainder = (sum * 10) % 11;
        if (remainder === 10 || remainder === 11) remainder = 0;
        if (remainder !== parseInt(cpf.substring(9, 10))) return false;
        sum = 0;
        for (let i = 1; i <= 10; i++) sum += parseInt(cpf.substring(i-1, i)) * (12 - i);
        remainder = (sum * 10) % 11;
        if (remainder === 10 || remainder === 11) remainder = 0;
        return remainder === parseInt(cpf.substring(10, 11));
    },

    validateCNPJ(cnpj) {
        cnpj = cnpj.replace(/\D/g, '');
        if (cnpj.length !== 14) return false;
        let size = cnpj.length - 2, numbers = cnpj.substring(0, size), digits = cnpj.substring(size);
        let sum = 0, pos = size - 7;
        for (let i = size; i >= 1; i--) { sum += numbers.charAt(size - i) * pos--; if (pos < 2) pos = 9; }
        let result = sum % 11 < 2 ? 0 : 11 - sum % 11;
        if (result !== parseInt(digits.charAt(0))) return false;
        size++; numbers = cnpj.substring(0, size); sum = 0; pos = size - 7;
        for (let i = size; i >= 1; i--) { sum += numbers.charAt(size - i) * pos--; if (pos < 2) pos = 9; }
        result = sum % 11 < 2 ? 0 : 11 - sum % 11;
        return result === parseInt(digits.charAt(1));
    },

    validateEmail(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    },

    validatePhone(phone) {
        return phone.replace(/\D/g, '').length >= 10;
    },

    validateForm(fields) {
        const errors = [];
        fields.forEach(f => {
            const el = document.getElementById(f.id);
            if (!el) return;
            const val = el.value.trim();
            if (f.required && !val) errors.push(`${f.label} é obrigatório`);
            if (val && f.type === 'cpf' && !this.validateCPF(val)) errors.push(`${f.label} inválido`);
            if (val && f.type === 'cnpj' && !this.validateCNPJ(val)) errors.push(`${f.label} inválido`);
            if (val && f.type === 'email' && !this.validateEmail(val)) errors.push(`${f.label} inválido`);
            if (val && f.type === 'phone' && !this.validatePhone(val)) errors.push(`${f.label} inválido`);
        });
        return errors;
    },

    // ===== HASH =====
    async sha256(message) {
        const encoder = new TextEncoder();
        const data = encoder.encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    },

    // ===== TOAST =====
    toast(message, type = 'success', duration = 3000) {
        let container = document.querySelector('.toast-container');
        if (!container) {
            container = document.createElement('div');
            container.className = 'toast-container';
            document.body.appendChild(container);
        }
        const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `<span>${icons[type]}</span><span>${this.escapeHtml(message)}</span>`;
        container.appendChild(toast);
        setTimeout(() => {
            toast.classList.add('removing');
            setTimeout(() => toast.remove(), 300);
        }, duration);
    },

    // ===== CONFIRMAÇÃO =====
    confirm(message, onConfirm, onCancel = null) {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay active';
        overlay.style.zIndex = '2500';
        overlay.innerHTML = `
            <div class="modal-content" style="max-width: 400px;">
                <h3>⚠️ Confirmação</h3>
                <p style="margin: 15px 0; line-height: 1.5;">${this.escapeHtml(message)}</p>
                <div class="modal-buttons">
                    <button class="btn btn-danger" id="confirmYes">Confirmar</button>
                    <button class="btn btn-outline" id="confirmNo">Cancelar</button>
                </div>
            </div>
        `;
        document.body.appendChild(overlay);
        overlay.querySelector('#confirmYes').onclick = () => { overlay.remove(); onConfirm(); };
        overlay.querySelector('#confirmNo').onclick = () => { overlay.remove(); if (onCancel) onCancel(); };
        overlay.onclick = (e) => { if (e.target === overlay) { overlay.remove(); if (onCancel) onCancel(); } };
    },

    // ===== PAGINAÇÃO =====
    paginate(items, page, perPage = 10) {
        const total = items.length;
        const totalPages = Math.ceil(total / perPage);
        const currentPage = Math.max(1, Math.min(page, totalPages || 1));
        const start = (currentPage - 1) * perPage;
        const end = start + perPage;
        return {
            items: items.slice(start, end),
            currentPage, totalPages, total,
            hasNext: currentPage < totalPages,
            hasPrev: currentPage > 1
        };
    },

    // ===== DATA E HORA =====
    formatDateBR(dateStr) {
        if (!dateStr) return '';
        const [year, month, day] = dateStr.split('-');
        return `${day}/${month}/${year}`;
    },

    formatDateLong(dateStr) {
        if (!dateStr) return '';
        const date = new Date(dateStr + 'T00:00:00');
        return date.toLocaleDateString('pt-BR', { day: '2-digit', month: 'long', year: 'numeric' });
    },

    formatCurrency(value) {
        return parseFloat(value || 0).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
    },

    // ===== STORAGE SEGURO COM QUOTA =====
    async safeSet(key, data) {
        try {
            const encrypted = await this.encrypt(data);
            const json = JSON.stringify(encrypted);
            localStorage.setItem(key, json);
        } catch (e) {
            if (e.name === 'QuotaExceededError' || e.message.includes('quota')) {
                this.toast('⚠️ Armazenamento cheio! Exporte backup e limpe dados antigos.', 'warning', 8000);
            }
            try {
                localStorage.setItem(key, JSON.stringify(data));
            } catch (e2) {
                this.toast('❌ Erro ao salvar dados. Armazenamento cheio!', 'error', 5000);
            }
        }
    },

    async safeGet(key, defaultValue = null) {
        try {
            const stored = localStorage.getItem(key);
            if (!stored) return defaultValue;
            const parsed = JSON.parse(stored);
            if (parsed && parsed.iv && Array.isArray(parsed.iv)) {
                return await this.decrypt(parsed);
            }
            return parsed;
        } catch (e) {
            return defaultValue;
        }
    },

    // ===== NOTIFICAÇÃO PUSH =====
    async requestNotificationPermission() {
        if (!('Notification' in window)) return false;
        const permission = await Notification.requestPermission();
        return permission === 'granted';
    },

    sendNotification(title, options = {}) {
        if (Notification.permission === 'granted') {
            new Notification(title, {
                icon: '/icon-192x192.png',
                badge: '/icon-72x72.png',
                ...options
            });
        }
    },

    // ===== BACKUP POR ARQUIVO =====
    exportToFile(filename = null) {
        const data = {
            version: '4.2',
            exportedAt: new Date().toISOString(),
            device: navigator.userAgent,
            orcamento: JSON.parse(localStorage.getItem('dj_brow_orcamento_data_v4') || '{}'),
            historico: JSON.parse(localStorage.getItem('dj_brow_contracts_history') || '[]'),
            contrato: JSON.parse(localStorage.getItem('dj_brow_contract_data_v3') || '{}'),
            signature: localStorage.getItem('dj_brow_signature_v2') || localStorage.getItem('dj_brow_signature'),
            cryptoKey: localStorage.getItem('dj_brow_crypto_key'),
            recibos: {},
            sequencias: {}
        };
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith('dj_brow_recibo_num_')) data.recibos[key] = localStorage.getItem(key);
            if (key && key.startsWith('dj_brow_contract_seq_')) data.sequencias[key] = localStorage.getItem(key);
        }
        const json = JSON.stringify(data, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        const date = new Date().toISOString().split('T')[0];
        a.download = filename || `dj_brow_backup_${date}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        localStorage.setItem('dj_brow_last_backup', new Date().toDateString());
        return true;
    },

    async importFromFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = async (e) => {
                try {
                    const data = JSON.parse(e.target.result);
                    if (!data.version) throw new Error('Arquivo de backup inválido');

                    const confirmRestore = confirm(
                        `Restaurar backup de ${new Date(data.exportedAt).toLocaleString('pt-BR')}?\n\n` +
                        `Este backup contém:\n` +
                        `• ${(data.historico || []).length} eventos no histórico\n` +
                        `• Dados do orçamento\n` +
                        `• Dados do contratado\n\n` +
                        `⚠️ Isso SUBSTITUIRÁ seus dados atuais!`
                    );
                    if (!confirmRestore) { resolve(false); return; }

                    if (data.orcamento) localStorage.setItem('dj_brow_orcamento_data_v4', JSON.stringify(data.orcamento));
                    if (data.historico) localStorage.setItem('dj_brow_contracts_history', JSON.stringify(data.historico));
                    if (data.contrato) localStorage.setItem('dj_brow_contract_data_v3', JSON.stringify(data.contrato));
                    if (data.signature) localStorage.setItem('dj_brow_signature_v2', data.signature);
                    if (data.cryptoKey) localStorage.setItem('dj_brow_crypto_key', data.cryptoKey);
                    if (data.recibos) Object.keys(data.recibos).forEach(key => localStorage.setItem(key, data.recibos[key]));
                    if (data.sequencias) Object.keys(data.sequencias).forEach(key => localStorage.setItem(key, data.sequencias[key]));

                    resolve(true);
                } catch (err) { reject(err); }
            };
            reader.onerror = () => reject(new Error('Erro ao ler arquivo'));
            reader.readAsText(file);
        });
    },

    // ===== CONTADOR DE RECIBO =====
    getNextReceiptNumber() {
        const year = new Date().getFullYear();
        const key = `dj_brow_recibo_num_${year}`;
        let current = parseInt(localStorage.getItem(key) || '0');
        current++;
        localStorage.setItem(key, current.toString());
        return `${year}-${current.toString().padStart(4, '0')}`;
    },

    // ===== NÚMERO DE CONTRATO SEQUENCIAL =====
    generateContractNumber() {
        const year = new Date().getFullYear();
        const key = `dj_brow_contract_seq_${year}`;
        let seq = parseInt(localStorage.getItem(key) || '0') + 1;
        localStorage.setItem(key, seq.toString());
        return `${year}-${seq.toString().padStart(4, '0')}`;
    },

    // ===== CALCULAR COUNTDOWN =====
    calculateCountdown(dateStr) {
        const eventDate = new Date(dateStr + 'T00:00:00');
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const diff = Math.ceil((eventDate - today) / (1000 * 60 * 60 * 24));
        if (diff === 0) return { text: 'É HOJE! 🎧', class: 'countdown-today', urgent: true };
        if (diff > 0) return { text: `Faltam ${diff} dias`, class: 'countdown-future', urgent: diff <= 7 };
        return { text: 'Realizado', class: 'countdown-past', urgent: false };
    },

    // ===== ASSINATURA DIGITAL MELHORADA =====
    async saveSignature(canvas, signerName, documentContent = '') {
        if (!canvas) throw new Error('Canvas não encontrado');

        // Verificar se canvas tem conteúdo
        const ctx = canvas.getContext('2d');
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const hasContent = imageData.data.some((v, i) => i % 4 === 3 && v > 0);
        if (!hasContent) throw new Error('Assinatura em branco. Desenhe antes de salvar.');

        const timestamp = new Date().toISOString();
        const hash = documentContent ? await this.sha256(documentContent) : '';

        const signatureData = {
            version: '2.0',
            imagem: canvas.toDataURL('image/png'),
            dataHora: timestamp,
            documentoHash: hash,
            signatario: signerName || 'Não identificado',
            tipo: 'assinatura_digital_nao_certificada',
            userAgent: navigator.userAgent,
            tela: { width: screen.width, height: screen.height }
        };

        localStorage.setItem('dj_brow_signature_v2', JSON.stringify(signatureData));
        return signatureData;
    },

    loadSignature() {
        const saved = localStorage.getItem('dj_brow_signature_v2');
        if (saved) {
            try { return JSON.parse(saved); } catch(e) { return null; }
        }
        // Fallback para versão antiga
        const old = localStorage.getItem('dj_brow_signature');
        if (old) return { imagem: old, version: '1.0' };
        return null;
    },

    // ===== RESIZE CANVAS RESPONSIVO =====
    resizeCanvas(canvas, container) {
        if (!canvas || !container) return;
        const rect = container.getBoundingClientRect();
        const dpr = window.devicePixelRatio || 1;

        // Salvar conteúdo atual se existir
        let tempCanvas = null;
        if (canvas.width > 0 && canvas.height > 0) {
            tempCanvas = document.createElement('canvas');
            tempCanvas.width = canvas.width;
            tempCanvas.height = canvas.height;
            tempCanvas.getContext('2d').drawImage(canvas, 0, 0);
        }

        canvas.width = rect.width * dpr;
        canvas.height = 200 * dpr;
        canvas.style.width = rect.width + 'px';
        canvas.style.height = '200px';

        const ctx = canvas.getContext('2d');
        ctx.scale(dpr, dpr);
        ctx.lineCap = 'round';
        ctx.lineJoin = 'round';
        ctx.lineWidth = 2;
        ctx.strokeStyle = '#000';

        // Restaurar conteúdo
        if (tempCanvas) {
            ctx.drawImage(tempCanvas, 0, 0, rect.width, 200);
        }
    },

    // ===== CSV EXPORT =====
    exportToCSV(data, filename) {
        if (!data || !data.length) return;
        const headers = Object.keys(data[0]);
        const rows = data.map(row => headers.map(h => {
            const val = row[h] || '';
            return `"${String(val).replace(/"/g, '""')}"`;
        }).join(','));
        const csv = [headers.join(','), ...rows].join('\n');
        const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename || `export_${new Date().toISOString().split('T')[0]}.csv`;
        a.click();
        URL.revokeObjectURL(url);
    }
};

// Inicializar crypto ao carregar
DJ_BROWW.initCrypto();

// Expor globalmente
window.DJ_BROWW = DJ_BROWW;
