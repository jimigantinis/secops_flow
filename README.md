# SecOps Flow

> 🇧🇷 **Português abaixo** — [Clique aqui para ir à versão em português](#-secops-flow--versão-em-português)

---

A unified analyst toolkit for Security Operations teams. Investigate IOCs, analyze suspicious emails, explore the MITRE ATT&CK framework, and get AI-guided incident response — all in one place, with no backend required.

🔗 **Live demo:** [jimigantinis.github.io/secops_flow](https://jimigantinis.github.io/secops_flow/)

---

## Features

| Module | Description |
|--------|-------------|
| **IOC Lookup** | Real-time threat intelligence for IPs, file hashes, domains, and CVEs. Integrates AbuseIPDB and VirusTotal APIs (user-provided keys), plus free geo-data via IPInfo.io. Includes external links to IBM X-Force, Shodan, GreyNoise, URLScan, and Talos. |
| **Email Header Analyzer** | Paste raw email headers and get instant analysis of SPF, DKIM, DMARC, relay path, suspicious indicators, and sender reputation. |
| **MITRE ATT&CK Explorer** | Browse and search the MITRE ATT&CK matrix. View detailed technique descriptions, detection guidance, mitigation steps, and procedure examples. Links directly to the official MITRE site when needed. |
| **AI Consultant** | Offline AI assistant based on scenario matching. Describe your incident in natural language and receive structured investigation checklists, mapped TTPs, and tool recommendations — no external API required. |

---

## Tech Stack

- **React 18** + **Vite** — SPA frontend
- **React Router v6** (HashRouter for static hosting compatibility)
- **Tailwind CSS v4** — utility-first styling
- **Lucide React** — icon library
- **Offline-first** — no backend, no data leaves your browser

---

## Getting Started

### Prerequisites

- Node.js 18+
- npm 9+

### Installation

```bash
git clone https://github.com/jimigantinis/secops_flow.git
cd secops_flow
npm install
npm run dev
```

The app will be available at `http://localhost:5173`.

### Build for Production

```bash
npm run build
```

Output goes to the `dist/` folder.

---

## API Keys Configuration

SecOps Flow is **fully functional without any API keys** — it will display geo-location data (via IPInfo.io) and links to external tools.

To unlock real-time threat intelligence, add your free API keys directly in the app:

1. Open the app and go to **IOC Lookup**
2. Click **"Configurar API Keys"** (top right)
3. Paste your keys — they are saved locally in your browser (`localStorage`) and **never sent to any server**

| Service | What it unlocks | How to get a free key |
|---------|----------------|----------------------|
| **AbuseIPDB** | Abuse confidence score, report count, ISP, usage type | [abuseipdb.com](https://www.abuseipdb.com/account/api) → Account → API |
| **VirusTotal** | Malicious/suspicious engine count, community score, AS info | [virustotal.com](https://www.virustotal.com) → Profile → API Key |

> **Security note:** Keys are stored only in your browser's localStorage. They are never committed to the repository or sent to any external service other than the respective APIs.

---

## Deploy to GitHub Pages

This repository includes a GitHub Actions workflow for automatic deployment.

1. Fork or push to a repository on GitHub
2. Go to **Settings → Pages → Source** and select **"GitHub Actions"**
3. Push any change to `main` — the workflow builds and deploys automatically

---

## Project Structure

```
src/
├── views/
│   ├── Home.jsx                # Dashboard / landing
│   ├── IOCLookup.jsx           # IP/Hash/Domain/CVE lookup
│   ├── EmailHeaderAnalyzer.jsx # Email header parser
│   ├── MitreExplorer.jsx       # MITRE ATT&CK browser
│   └── AIConsultant.jsx        # Offline AI assistant
├── services/
│   └── threatIntelApi.js       # API call functions (AbuseIPDB, VT, ipinfo, NVD)
├── data/
│   └── knowledgeBase.js        # AI scenarios + MITRE technique data
└── App.jsx                     # Router + layout
```

---

## License

Apache-2.0 — feel free to use, modify, and distribute.

---
---

# 🇧🇷 SecOps Flow — Versão em Português

Uma plataforma unificada para analistas de segurança. Investigue IoCs, analise e-mails suspeitos, explore o MITRE ATT&CK e consulte a IA para resposta a incidentes — tudo em um só lugar, sem necessidade de backend.

🔗 **Demo ao vivo:** [jimigantinis.github.io/secops_flow](https://jimigantinis.github.io/secops_flow/)

---

## Funcionalidades

| Módulo | Descrição |
|--------|-----------|
| **IOC Lookup** | Verificação em tempo real de IPs, hashes de arquivos, domínios e CVEs. Integra as APIs do AbuseIPDB e VirusTotal (chaves do próprio usuário), além de dados geográficos gratuitos via IPInfo.io. Links externos para IBM X-Force, Shodan, GreyNoise, URLScan e Talos. |
| **Análise de Cabeçalho de E-mail** | Cole os cabeçalhos brutos de um e-mail e obtenha análise imediata de SPF, DKIM, DMARC, caminho de relay, indicadores suspeitos e reputação do remetente. |
| **MITRE ATT&CK Explorer** | Navegue e pesquise a matriz MITRE ATT&CK. Veja descrições detalhadas de técnicas, orientações de detecção, passos de mitigação e exemplos de procedimentos reais. |
| **AI Consultor** | Assistente de IA offline baseado em correspondência de cenários. Descreva seu incidente em linguagem natural e receba checklists de investigação, TTPs mapeados e recomendações de ferramentas — sem API externa. |

---

## Stack de Tecnologia

- **React 18** + **Vite** — SPA frontend
- **React Router v6** (HashRouter para compatibilidade com hospedagem estática)
- **Tailwind CSS v4** — estilização utilitária
- **Lucide React** — biblioteca de ícones
- **Offline-first** — sem backend, nenhum dado sai do navegador

---

## Como Rodar Localmente

### Pré-requisitos

- Node.js 18+
- npm 9+

### Instalação

```bash
git clone https://github.com/jimigantinis/secops_flow.git
cd secops_flow
npm install
npm run dev
```

Acesse em `http://localhost:5173`.

### Gerar Build de Produção

```bash
npm run build
```

A saída vai para a pasta `dist/`.

---

## Configuração de API Keys

O SecOps Flow funciona **completamente sem API Keys** — mostrará dados de geolocalização (via IPInfo.io) e links para ferramentas externas.

Para ativar a inteligência de ameaças em tempo real, adicione suas chaves gratuitas diretamente no app:

1. Abra o app e vá em **IOC Lookup**
2. Clique em **"Configurar API Keys"** (canto superior direito)
3. Cole suas chaves — elas ficam salvas localmente no seu navegador (`localStorage`) e **nunca são enviadas a nenhum servidor**

| Serviço | O que ativa | Como obter a chave gratuita |
|---------|-------------|----------------------------|
| **AbuseIPDB** | Score de abuso, número de reports, ISP, tipo de uso | [abuseipdb.com](https://www.abuseipdb.com/account/api) → Account → API |
| **VirusTotal** | Contagem de engines, community score, info de AS | [virustotal.com](https://www.virustotal.com) → Profile → API Key |

> **Segurança:** As chaves ficam apenas no localStorage do seu navegador. Nunca são commitadas no repositório nem enviadas a nenhum serviço além das APIs respectivas.

---

## Deploy no GitHub Pages

Este repositório inclui um workflow do GitHub Actions para deploy automático.

1. Faça fork ou suba para um repositório no GitHub
2. Vá em **Settings → Pages → Source** e selecione **"GitHub Actions"**
3. Faça push para `main` — o workflow faz o build e o deploy automaticamente

---

## Estrutura do Projeto

```
src/
├── views/
│   ├── Home.jsx                # Tela inicial
│   ├── IOCLookup.jsx           # Lookup de IP/Hash/Domínio/CVE
│   ├── EmailHeaderAnalyzer.jsx # Análise de cabeçalho de e-mail
│   ├── MitreExplorer.jsx       # Navegador do MITRE ATT&CK
│   └── AIConsultant.jsx        # Assistente IA offline
├── services/
│   └── threatIntelApi.js       # Funções de chamada de API
├── data/
│   └── knowledgeBase.js        # Cenários da IA + dados MITRE
└── App.jsx                     # Roteador + layout
```

---

## Licença

Apache-2.0 — livre para usar, modificar e distribuir.
