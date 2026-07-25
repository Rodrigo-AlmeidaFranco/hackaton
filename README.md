# STRIDE AI Threat Modeler

**Hackathon FIAP Software Security** — Modelagem de ameaças com IA usando metodologia STRIDE.

## Visão Geral

Sistema que interpreta automaticamente diagramas de arquitetura de software (imagens), detecta os componentes via modelo supervisionado YOLOv8, e gera um relatório completo de **Modelagem de Ameaças STRIDE** potencializado por Claude AI.

```
Diagrama (imagem) → YOLOv8 (detecção) → STRIDE Engine + Claude AI → Relatório PDF
```

## Arquitetura da Solução

```
hackaton/
├── dataset/                  # Dataset sintético gerado automaticamente
│   ├── images/{train,val,test}/
│   ├── labels/{train,val,test}/   # Anotações YOLO (class cx cy w h)
│   └── data.yaml
├── src/
│   ├── dataset/generator.py  # Gerador de diagramas sintéticos + anotações automáticas
│   ├── model/
│   │   ├── trainer.py        # Pipeline de treinamento YOLOv8
│   │   └── detector.py       # Inferência e pós-processamento
│   ├── stride/analyzer.py    # Análise STRIDE com Claude AI
│   ├── vulnerabilities/database.py  # Base de conhecimento de ameaças
│   └── report/generator.py   # Geração de relatório PDF
├── models/arch_detector/     # Pesos treinados YOLOv8
├── train.py                  # Script de treinamento end-to-end
└── app.py                    # Interface Streamlit
```

## Componentes Detectados (12 classes)

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

## Metodologia STRIDE

| Categoria | Ameaça |
|-----------|--------|
| **S** | Spoofing (autenticação) |
| **T** | Tampering (integridade) |
| **R** | Repudiation (não-repúdio) |
| **I** | Information Disclosure (confidencialidade) |
| **D** | Denial of Service (disponibilidade) |
| **E** | Elevation of Privilege (autorização) |

## Instalação

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Uso

### 1. Gerar Dataset + Treinar Modelo

```bash
python train.py
```

Opções avançadas:
```bash
python train.py --n-train 500 --epochs 100 --model-size s
```

### 2. Lançar Interface Web

```bash
export ANTHROPIC_API_KEY=sk-ant-...
streamlit run app.py
```

### 3. Apenas gerar dataset (sem treinar)

```bash
python -c "
from src.dataset.generator import ArchitectureDiagramGenerator
gen = ArchitectureDiagramGenerator('dataset')
gen.generate_dataset(n_train=300, n_val=60, n_test=40)
"
```

## Pipeline Técnico

### Dataset Sintético
- **400 imagens** geradas programaticamente (300 train / 60 val / 40 test)
- **8 templates** de arquitetura: 3-tier, AWS VPC, Microservices, Azure API, Mobile Backend, Event-Driven, CDN Static, Simple SaaS
- Variações aleatórias de posição, cor, escala, labels e conexões
- Anotações YOLO geradas automaticamente (bounding boxes exatos)

### Modelo Supervisionado (YOLOv8)
- Base: YOLOv8-nano pré-treinado (transfer learning)
- 3M parâmetros, 8.2 GFLOPs
- Resultados típicos: **mAP50 > 0.99**, mAP50-95 > 0.98

### Análise STRIDE
1. Componentes detectados → mapeamento na knowledge base de vulnerabilidades
2. Claude AI gera análise narrativa contextualizada para a arquitetura específica
3. Ameaças por data flow (caminho entre componentes)
4. Recomendações priorizadas

### Relatório PDF
- Capa com nível de risco geral
- Imagem anotada com bounding boxes
- Resumo executivo (gerado por IA)
- Matriz STRIDE completa
- Detalhamento por componente (CWEs, contramedidas)
- Ameaças nos fluxos de dados
- Recomendações priorizadas

## Resultados de Treinamento

| Época | mAP50 | mAP50-95 | Precision | Recall |
|-------|-------|----------|-----------|--------|
| 5 | 0.961 | 0.904 | 0.962 | 0.973 |
| 8 | 0.995 | 0.980 | 0.991 | 1.000 |
| 15 | 0.993 | 0.983 | 0.985 | 0.968 |

## Arquiteturas de Avaliação

O sistema foi testado com os diagramas oficiais do hackathon disponíveis em `examples/`:

| Arquivo | Arquitetura | Componentes esperados |
|---------|-------------|----------------------|
| `examples/arquitetura1_aws.jpg` | AWS Multi-AZ (sa-east-1) | Users, CloudFront (CDN), WAF (Firewall), AWS Shield, 3x ALB (Load Balancer), EC2/SEI (Web Server), RDS Primary + Secondary (Database), ElastiCache (Cache), EFS, Solr |
| `examples/arquitetura2_azure.jpg` | Azure API Management | User (Internet), Microsoft Entra (Cloud Service), API Gateway, Logic Apps (Cloud Service), Developer Portal (Web Server), Azure/SaaS/REST/SOAP (External Services) |

> **Nota:** Os diagramas usam ícones reais AWS/Azure. Para melhor detecção recomenda-se ativar o **Modo Híbrido** (YOLOv8 + Llama Vision) na interface.

## Entregáveis

- [x] Código-fonte completo no GitHub
- [x] Dataset sintético com anotações automáticas
- [x] Modelo YOLOv8 treinado e avaliado
- [x] Sistema de análise STRIDE com IA
- [x] Knowledge base de vulnerabilidades (12 componentes, 30+ ameaças, 150+ contramedidas)
- [x] Interface web Streamlit
- [x] Geração de relatório PDF profissional
- [x] Documentação detalhando o fluxo (este README)
- [x] Imagens de avaliação do hackathon (`examples/`)
- [ ] Vídeo de apresentação (até 15 min)
