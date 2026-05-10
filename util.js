/**
 * DJ BROWW - Utilitários Compartilhados v4.0
 * Criptografia, sanitização, máscaras, notificações, paginação
 */

const DJ_BROWW = {
    version: '4.0',
    cryptoKey: null,

    // ===== CRIPTOGRAFIA AES =====
    async initCrypto() {
        const savedKey = localStorage.getItem('dj_brow_crypto_key');
        if (savedKey) {
            const keyData = JSON.parse(savedKey);
            this.cryptoKey = await crypto.subtle.importKey(
                'jwk', keyData, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
            );
        }
    },

    async generateKey(password) {
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
        if (!this.cryptoKey) return data;
        const encoder = new TextEncoder();
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            this.cryptoKey,
            encoder.encode(JSON.stringify(data))
        );
        return {
            iv: Array.from(iv),
            data: Array.from(new Uint8Array(encrypted))
        };
    },

    async decrypt(encryptedObj) {
        if (!this.cryptoKey || !encryptedObj.iv) return encryptedObj;
        const iv = new Uint8Array(encryptedObj.iv);
        const data = new Uint8Array(encryptedObj.data);
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            this.cryptoKey,
            data
        );
        const decoder = new TextDecoder();
        return JSON.parse(decoder.decode(decrypted));
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

    // ===== VALIDAÇÃO =====
    validateCPF(cpf) {
        cpf = cpf.replace(/\D/g, '');
        if (cpf.length !== 11 || /^(.)+$/.test(cpf)) return false;
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

    // ===== HASH PARA ASSINATURA =====
    async sha256(message) {
        const encoder = new TextEncoder();
        const data = encoder.encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    },

    // ===== NOTIFICAÇÕES TOAST =====
    toast(message, type = 'success', duration = 3000) {
        let container = document.querySelector('.toast-container');
        if (!container) {
            container = document.createElement('div');
            container.className = 'toast-container';
            document.body.appendChild(container);
        }

        const icons = {
            success: '✅',
            error: '❌',
            warning: '⚠️',
            info: 'ℹ️'
        };

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `<span>${icons[type]}</span><span>${this.escapeHtml(message)}</span>`;
        container.appendChild(toast);

        setTimeout(() => {
            toast.classList.add('removing');
            setTimeout(() => toast.remove(), 300);
        }, duration);
    },

    // ===== CONFIRMAÇÃO MODAL =====
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

        overlay.querySelector('#confirmYes').onclick = () => {
            overlay.remove();
            onConfirm();
        };
        overlay.querySelector('#confirmNo').onclick = () => {
            overlay.remove();
            if (onCancel) onCancel();
        };
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
            currentPage,
            totalPages,
            total,
            hasNext: currentPage < totalPages,
            hasPrev: currentPage > 1
        };
    },

    renderPagination(container, pagination, onPageChange) {
        if (pagination.totalPages <= 1) {
            container.innerHTML = '';
            return;
        }

        let html = '<div class="pagination">';
        html += `<button ${pagination.hasPrev ? '' : 'disabled'} onclick="${onPageChange}(${pagination.currentPage - 1})">←</button>`;

        for (let i = 1; i <= pagination.totalPages; i++) {
            if (i === 1 || i === pagination.totalPages || (i >= pagination.currentPage - 1 && i <= pagination.currentPage + 1)) {
                html += `<button class="${i === pagination.currentPage ? 'active' : ''}" onclick="${onPageChange}(${i})">${i}</button>`;
            } else if (i === pagination.currentPage - 2 || i === pagination.currentPage + 2) {
                html += '<span style="color:#666;">...</span>';
            }
        }

        html += `<button ${pagination.hasNext ? '' : 'disabled'} onclick="${onPageChange}(${pagination.currentPage + 1})">→</button>`;
        html += '</div>';
        html += `<div class="pagination-info">Mostrando ${(pagination.currentPage - 1) * 10 + 1}-${Math.min(pagination.currentPage * 10, pagination.total)} de ${pagination.total}</div>`;

        container.innerHTML = html;
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

    // ===== STORAGE SEGURO =====
    async safeSet(key, data) {
        try {
            const encrypted = await this.encrypt(data);
            localStorage.setItem(key, JSON.stringify(encrypted));
        } catch (e) {
            localStorage.setItem(key, JSON.stringify(data));
        }
    },

    async safeGet(key, defaultValue = null) {
        try {
            const stored = localStorage.getItem(key);
            if (!stored) return defaultValue;
            const parsed = JSON.parse(stored);
            if (parsed.iv) {
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

    // ===== EXPORTAR PDF =====
    async generatePDF(elementId, filename) {
        const element = document.getElementById(elementId);
        if (!element) return;

        // Usar print otimizado
        const originalTitle = document.title;
        document.title = filename.replace('.pdf', '');

        // Adicionar classe de print
        element.classList.add('print-optimized');

        window.print();

        // Restaurar
        setTimeout(() => {
            document.title = originalTitle;
            element.classList.remove('print-optimized');
        }, 1000);
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

    // ===== CALCULAR COUNTDOWN =====
    calculateCountdown(dateStr) {
        const eventDate = new Date(dateStr + 'T00:00:00');
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const diff = Math.ceil((eventDate - today) / (1000 * 60 * 60 * 24));
        if (diff === 0) return { text: 'É HOJE! 🎧', class: 'countdown-today', urgent: true };
        if (diff > 0) return { text: `Faltam ${diff} dias`, class: 'countdown-future', urgent: diff <= 7 };
        return { text: 'Realizado', class: 'countdown-past', urgent: false };
    }
};

// Inicializar crypto ao carregar
DJ_BROWW.initCrypto();

// Expor globalmente
window.DJ_BROWW = DJ_BROWW;
