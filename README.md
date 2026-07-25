# STRIDE AI Threat Modeler

**Hackathon FIAP Software Security** — Modelagem de ameaças com IA usando metodologia STRIDE.

## Visão Geral

Sistema que interpreta automaticamente diagramas de arquitetura de software (imagens), detecta os componentes via modelo supervisionado YOLOv8, e gera um relatório completo de **Modelagem de Ameaças STRIDE** potencializado por múltiplos backends de LLM.

```
Diagrama (imagem) → YOLOv8 (detecção) → [opcional: Llama Vision] → STRIDE Engine + LLM → Relatório PDF
```

## Arquitetura da Solução

```
hackaton/
├── dataset/                        # Dataset sintético v1 (12 classes genéricas)
│   ├── images/{train,val,test}/
│   ├── labels/{train,val,test}/
│   └── data.yaml
├── dataset_v2/                     # Dataset real v2 (111 classes AWS/Azure/GCP)
│   ├── images/{train,val,test}/    # Symlinks para o dataset original
│   ├── labels/{train,val,test}/    # Anotações YOLO convertidas de Pascal VOC
│   └── data.yaml
├── scripts/
│   └── prepare_dataset.py          # Conversor Pascal VOC XML → YOLO (v2)
├── src/
│   ├── dataset/generator.py        # Gerador sintético + COMPONENT_CLASSES v1/v2
│   ├── model/
│   │   ├── trainer.py              # Pipeline de treinamento YOLOv8
│   │   ├── detector.py             # Inferência com auto-detecção v1/v2
│   │   └── hybrid_detector.py      # YOLOv8 + Llama Vision (modo híbrido)
│   ├── stride/analyzer.py          # Análise STRIDE com múltiplos backends LLM
│   ├── vulnerabilities/database.py # Knowledge base: 122 componentes, 400+ ameaças
│   └── report/generator.py         # Geração de relatório PDF
├── models/
│   ├── arch_detector/              # Modelo v1 (12 classes, mAP50=0.995)
│   └── arch_detector_v2/           # Modelo v2 (111 classes, dataset real)
├── train.py                        # Treino v1: dataset sintético
├── train_v2.py                     # Treino v2: dataset real AWS/Azure/GCP
└── app.py                          # Interface Streamlit
```

## Modelos Disponíveis

### v1 — 12 classes genéricas
Modelo treinado em dataset sintético gerado programaticamente. Alta precisão em diagramas genéricos.

| Classe | Descrição |
|--------|-----------|
| `user` | Usuário / Ator / Cliente |
| `web_server` | Servidor Web / Aplicação |
| `database` | Banco de Dados |
| `api_gateway` | API Gateway |
| `load_balancer` | Load Balancer |
| `cache` | Cache (Redis, Memcached) |
| `firewall` | Firewall / WAF |
| `cdn` | CDN / Content Delivery |
| `message_queue` | Fila de Mensagens |
| `cloud_service` | Serviço Cloud / Serverless |
| `mobile_app` | Aplicativo Mobile |
| `external_service` | Serviço Externo |

### v2 — 111 classes específicas AWS + Azure + GCP
Modelo treinado em dataset real com ícones oficiais dos cloud providers. Detecta serviços específicos como `aws_lambda`, `azure_kubernetes_services`, `gcp_bigquery`, etc.

**Cobertura:** 59 classes AWS · 31 classes Azure · 12 classes GCP · 9 genéricas

> O detector auto-detecta a versão do modelo carregado e seleciona a lista de classes correspondente.

## Metodologia STRIDE

| Categoria | Ameaça |
|-----------|--------|
| **S** | Spoofing — autenticação e identidade |
| **T** | Tampering — integridade de dados |
| **R** | Repudiation — não-repúdio e auditoria |
| **I** | Information Disclosure — confidencialidade |
| **D** | Denial of Service — disponibilidade |
| **E** | Elevation of Privilege — autorização |

## Backends de Análise LLM

| Backend | Modelo padrão | Requer chave |
|---------|---------------|:---:|
| Rule-Based | — (knowledge base local) | Não |
| Ollama (local) | `llama3.2` | Não |
| Groq | `llama-3.3-70b-versatile` | Sim |
| Google Gemini | `gemini-2.0-flash` | Sim |
| OpenAI / LM Studio | `gpt-4o-mini` | Sim |
| Anthropic Claude | `claude-sonnet-4-6` | Sim |

## Instalação

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Uso

### Lançar a Interface Web

```bash
streamlit run app.py
```

Sem LLM (offline):
- Selecione **"Rule-Based (sem LLM)"** na sidebar

Com Claude:
```bash
export ANTHROPIC_API_KEY=sk-ant-...
streamlit run app.py
```

Trocar para o modelo v2 (111 classes):
- No campo **"Caminho do Modelo YOLOv8"** informe: `models/arch_detector_v2/weights/best.pt`

---

### Treinar Modelo v1 (dataset sintético)

```bash
# Gera dataset + treina + avalia
python train.py

# Opções avançadas
python train.py --n-train 500 --epochs 100 --model-size s
```

### Treinar Modelo v2 (dataset real AWS/Azure/GCP)

**Pré-requisito:** dataset com anotações Pascal VOC XML em `~/Downloads/src/dataset/dataset_augmented/`

```bash
# 1. Converte XML → YOLO e prepara dataset_v2/ (apenas primeira vez)
# 2. Treina YOLOv8s por 50 epochs
python train_v2.py

# Apenas conversão do dataset
python scripts/prepare_dataset.py --source ~/Downloads/src/dataset/dataset_augmented

# Apenas treino (dataset já convertido)
python train_v2.py --skip-prepare --model-size s --epochs 50
```

---

## Pipeline Técnico

### Dataset v1 — Sintético
- **400 imagens** geradas programaticamente (300 train / 60 val / 40 test)
- **8 templates** de arquitetura: 3-tier, AWS VPC, Microservices, Azure API, Mobile Backend, Event-Driven, CDN Static, Simple SaaS
- Anotações YOLO geradas automaticamente (bounding boxes exatos)
- Estilos visuais: genérico, AWS e Azure

### Dataset v2 — Real
- **8.700 imagens** com ícones oficiais AWS, Azure e GCP
- Anotações originais em Pascal VOC XML, convertidas para YOLO por `scripts/prepare_dataset.py`
- Split: 70% treino / 15% val / 15% teste
- 111 classes com cobertura de todos os principais serviços cloud

### Detector (YOLOv8)
- Auto-detecção de versão: carrega `COMPONENT_CLASSES` (12) ou `COMPONENT_CLASSES_V2` (111) conforme o modelo
- Modo híbrido opcional: YOLOv8 localiza regiões → Llama Vision reclassifica cada crop
- `COMPONENT_DESCRIPTIONS` cobre todas as 111 classes para o prompt de visão

### Análise STRIDE
1. Componentes detectados → lookup na knowledge base (`database.py`)
2. LLM gera análise narrativa contextualizada para a arquitetura específica
3. Fallback automático para rule-based se a chamada ao LLM falhar
4. Ameaças por data flow entre pares de componentes
5. Recomendações priorizadas por severidade

### Knowledge Base
- **122 entradas** de componentes com mapeamento STRIDE completo
- Templates de ameaças por categoria funcional: compute, database, storage, IAM, ML/AI, networking, containers, serverless, DevOps, monitoramento
- Cada ameaça inclui: descrição, severidade, contramedidas e CWE IDs
- Cobertura: 100% das 111 classes v2

### Relatório PDF
- Capa com nível de risco geral (Critical / High / Medium / Low)
- Imagem anotada com bounding boxes
- Resumo executivo gerado por IA
- Matriz STRIDE completa por categoria
- Detalhamento por componente (CWEs, contramedidas)
- Ameaças nos fluxos de dados entre componentes
- Recomendações priorizadas por esforço e impacto

## Resultados de Treinamento

### Modelo v1 (sintético, 12 classes)

| Época | mAP50 | mAP50-95 | Precision | Recall |
|-------|-------|----------|-----------|--------|
| 5 | 0.961 | 0.904 | 0.962 | 0.973 |
| 8 | 0.995 | 0.980 | 0.991 | 1.000 |
| 15 | 0.993 | 0.983 | 0.985 | 0.968 |

### Modelo v2 (real, 111 classes)

| Configuração | mAP50 | mAP50-95 |
|--------------|-------|----------|
| 3 epochs, 1500 imgs (validação) | 0.138 | 0.105 |
| 50 epochs, 8700 imgs (recomendado) | — | — |

> Para o modelo v2 atingir alta precisão, recomenda-se treinar com o dataset completo (8.700 imagens) por 50+ epochs, preferencialmente com GPU.

## Arquiteturas de Avaliação

| Arquivo | Arquitetura | Componentes esperados |
|---------|-------------|----------------------|
| `examples/arquitetura1_aws.jpg` | AWS Multi-AZ (sa-east-1) | Users, CloudFront, WAF, ALB, EC2, RDS, ElastiCache, EFS, Solr |
| `examples/arquitetura2_azure.jpg` | Azure API Management | User, Microsoft Entra, API Gateway, Logic Apps, Developer Portal, SaaS/REST |

> Para diagramas com ícones reais AWS/Azure, ativar o **Modo Híbrido** (YOLOv8 + Llama Vision) melhora significativamente a precisão de classificação.

## Entregáveis

- [x] Código-fonte completo no GitHub
- [x] Dataset sintético v1 com anotações automáticas
- [x] Script de conversão Pascal VOC → YOLO para dataset v2
- [x] Modelo YOLOv8 v1 treinado (mAP50=0.995)
- [x] Modelo YOLOv8 v2 com suporte a 111 classes AWS/Azure/GCP
- [x] Sistema de análise STRIDE com 6 backends de LLM
- [x] Knowledge base: 122 componentes, 400+ ameaças, CWEs mapeados
- [x] Modo híbrido: YOLOv8 + Llama Vision para diagramas reais
- [x] Interface web Streamlit com download de relatório PDF
- [x] Documentação detalhando o fluxo (este README)
- [x] Imagens de avaliação do hackathon (`examples/`)
- [ ] Vídeo de apresentação (até 15 min)
