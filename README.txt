# DJ BROWW - Sistema de Gestão Profissional v4.0

## 🌐 Hospedado no GitHub Pages

Este sistema está otimizado para funcionar no GitHub Pages com HTTPS.

### Funcionalidades que agora funcionam:
- ✅ **Criptografia AES-256** — Ative a proteção com senha mestra
- ✅ **Instalar como App** — Botão aparece automaticamente no Chrome/Edge
- ✅ **Notificações Push** — Alertas de eventos próximos
- ✅ **Offline** — Funciona sem internet após primeiro acesso
- ✅ **Todos os módulos** — Orçamentos, contratos, histórico, ROI

---

## 📁 Estrutura de arquivos para GitHub Pages

Coloque todos estes arquivos na raiz do seu repositório:

```
📁 seu-repositorio/
├── 📄 index.html                          ← Página inicial
├── 📄 controleeorcamento.html             ← Orçamentos
├── 📄 dj_contract_juridico_atualizado.html ← Contratos
├── 📄 historico_contratos.html            ← Histórico financeiro
├── 📄 calculadora_roi.html                ← ROI
├── 📄 styles.css                          ← Estilos
├── 📄 util.js                             ← Funções compartilhadas
├── 📄 manifest.json                       ← Config PWA
├── 📄 sw.js                               ← Service Worker
├── 📄 icon-192x192.svg                    ← Ícone (substitua por PNG)
└── 📄 icon-512x512.svg                    ← Ícone (substitua por PNG)
```

---

## 🚀 Como publicar no GitHub Pages

1. Crie um repositório no GitHub
2. Faça upload de **todos** os arquivos acima
3. Vá em **Settings → Pages**
4. Em "Source", selecione **Deploy from a branch**
5. Escolha a branch **main** e pasta **/(root)**
6. Clique em **Save**
7. Aguarde 1-2 minutos e acesse o link gerado

---

## 🔒 Ativando a Criptografia

1. Abra o site publicado no GitHub Pages
2. No dashboard, clique em **"Ativar Proteção"**
3. Crie uma senha mestra (mínimo 6 caracteres)
4. Confirme a senha
5. Pronto! Seus dados estarão criptografados no navegador

---

## 📱 Instalando como App

### Android (Chrome):
1. Acesse o site no Chrome
2. Toque nos **3 pontos** → "Adicionar à tela inicial"
3. Ou aguarde o banner "Instalar DJ Brow" aparecer

### iOS (Safari):
1. Acesse o site no Safari
2. Toque no botão **Compartilhar** (quadrado com seta)
3. Role e toque em "Adicionar à Tela de Início"

### Desktop (Chrome/Edge):
1. Acesse o site
2. Clique no ícone **📱** na barra de endereço
3. Ou clique nos 3 pontos → "Instalar DJ Brow"

---

## ⚠️ Importante: Ícones

Os ícones inclusos são SVGs placeholder. Para melhor aparência:

1. Crie ícones PNG nos tamanhos: 72x72, 96x96, 128x128, 144x144, 152x152, 192x192, 384x384, 512x512
2. Substitua os arquivos SVG
3. Atualize o `manifest.json` com os caminhos dos PNGs

---

## 🔄 Atualizações

Para atualizar o app após mudanças:
1. Faça upload dos arquivos atualizados
2. Aguarde o GitHub Pages atualizar (1-2 min)
3. No app instalado, feche e abra novamente
4. O Service Worker atualizará automaticamente
