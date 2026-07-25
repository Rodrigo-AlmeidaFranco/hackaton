"""
Streamlit web application for STRIDE AI Threat Modeling.
Upload an architecture diagram image → detect components → generate STRIDE report.
"""

import io
import os
import sys
import tempfile
from pathlib import Path

import cv2
import numpy as np
import streamlit as st
from PIL import Image

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

from src.model.detector import ArchitectureDetector
from src.model.hybrid_detector import HybridDetector
from src.stride.analyzer import StrideAnalyzer
from src.report.generator import generate_report
from src.vulnerabilities.database import STRIDE as STRIDE_CATS, SEVERITY_COLORS as _SEV_C

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="STRIDE AI Threat Modeler",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .main-title { font-size: 2.2rem; font-weight: 800; color: #1A237E; }
    .subtitle   { font-size: 1.1rem; color: #555; margin-bottom: 1rem; }
    .metric-card {
        background: #F0F4FF; border-left: 5px solid #1A237E;
        border-radius: 8px; padding: 12px 16px; margin: 6px 0;
    }
    .sev-critical { color: #B71C1C; font-weight: bold; }
    .sev-high     { color: #E53935; font-weight: bold; }
    .sev-medium   { color: #FB8C00; font-weight: bold; }
    .sev-low      { color: #43A047; font-weight: bold; }
    .stride-badge {
        display: inline-block; padding: 2px 8px; border-radius: 4px;
        font-weight: bold; font-size: 0.8rem; margin: 2px;
    }
    .threat-card {
        border: 1px solid #E0E0E0; border-radius: 8px;
        padding: 12px; margin: 8px 0; background: #FAFAFA;
    }
</style>
""", unsafe_allow_html=True)

STRIDE_COLORS = {
    "S": "#E3F2FD", "T": "#FFF3E0", "R": "#F3E5F5",
    "I": "#E8F5E9", "D": "#FFEBEE", "E": "#FCE4EC",
}
STRIDE_TEXT_COLORS = {
    "S": "#1565C0", "T": "#E65100", "R": "#6A1B9A",
    "I": "#1B5E20", "D": "#B71C1C", "E": "#880E4F",
}

SEV_BADGE = {
    "Critical": "🔴 Critical",
    "High":     "🟠 High",
    "Medium":   "🟡 Medium",
    "Low":      "🟢 Low",
}


BACKEND_INFO = {
    "rule_based": {"label": "Rule-Based (sem LLM)", "needs_key": False,  "key_label": None},
    "ollama":     {"label": "Ollama (local)",        "needs_key": False,  "key_label": None},
    "groq":       {"label": "Groq (gratuito)",        "needs_key": True,   "key_label": "Groq API Key"},
    "gemini":     {"label": "Google Gemini",          "needs_key": True,   "key_label": "Gemini API Key"},
    "openai":     {"label": "OpenAI / LM Studio",     "needs_key": True,   "key_label": "OpenAI API Key"},
    "anthropic":  {"label": "Anthropic Claude",       "needs_key": True,   "key_label": "Anthropic API Key"},
}

BACKEND_DEFAULT_MODELS = {
    "ollama":    "llama3.2",
    "groq":      "llama-3.3-70b-versatile",
    "gemini":    "gemini-2.0-flash",
    "openai":    "gpt-4o-mini",
    "anthropic": "claude-sonnet-4-6",
}


def render_sidebar():
    with st.sidebar:
        st.markdown("## STRIDE AI Threat Modeler")
        st.markdown("*FIAP Software Security Hackathon*")
        st.divider()

        # ── LLM Backend selection ──────────────────────────────────────────
        st.markdown("**Backend de Análise STRIDE**")
        backend = st.selectbox(
            "Provedor LLM",
            options=list(BACKEND_INFO.keys()),
            format_func=lambda k: BACKEND_INFO[k]["label"],
            index=0,
        )

        api_key = None
        ollama_model = "llama3.2"
        ollama_url   = "http://localhost:11434"
        openai_base_url = None
        selected_model = BACKEND_DEFAULT_MODELS.get(backend, "")

        info = BACKEND_INFO[backend]

        if backend == "ollama":
            ollama_model = st.text_input("Modelo Ollama", value="llama3.2",
                                         help="Ex: llama3.2, mistral, qwen2.5, phi3")
            ollama_url = st.text_input("Ollama URL", value="http://localhost:11434")
            st.info("Execute: `ollama pull llama3.2` para baixar o modelo.")

        elif backend == "openai":
            api_key = st.text_input("OpenAI API Key", type="password",
                                    help="Deixe em branco para LM Studio local")
            openai_base_url = st.text_input("Base URL (opcional)",
                                            placeholder="http://localhost:1234/v1",
                                            help="Para LM Studio ou outro servidor OpenAI-compatível")
            selected_model = st.text_input("Modelo", value="gpt-4o-mini")
            if not openai_base_url:
                openai_base_url = None

        elif info["needs_key"]:
            key_label = info["key_label"]
            env_map = {
                "groq":      "GROQ_API_KEY",
                "gemini":    "GEMINI_API_KEY",
                "anthropic": "ANTHROPIC_API_KEY",
            }
            env_val = os.environ.get(env_map.get(backend, ""), "")
            api_key = st.text_input(key_label, type="password", value=env_val)
            if backend in BACKEND_DEFAULT_MODELS:
                selected_model = st.text_input("Modelo", value=BACKEND_DEFAULT_MODELS[backend])

        elif backend == "rule_based":
            st.success("Sem API key necessária. Análise baseada em knowledge base.")

        st.divider()

        # ── Model path + confidence ────────────────────────────────────────
        model_path_input = st.text_input(
            "Caminho do Modelo YOLOv8",
            value="models/arch_detector/weights/best.pt",
            help="Caminho para os pesos treinados",
        )
        confidence = st.slider(
            "Confiança de Detecção", min_value=0.1, max_value=0.9, value=0.20, step=0.05
        )
        use_vision = st.toggle(
            "Modo Híbrido (YOLOv8 + Llama Vision)",
            value=False,
            help="Usa llama3.2-vision para reclassificar cada componente detectado. "
                 "Melhora a precisão em diagramas reais AWS/Azure. "
                 "Requer: ollama pull llama3.2-vision",
        )
        if use_vision:
            st.info("Modo híbrido ativo: YOLO localiza, Llama Vision classifica.")

        st.divider()
        st.markdown("""
**Como usar:**
1. Envie um diagrama de arquitetura
2. Clique em **Analisar**
3. Veja os componentes detectados
4. Leia o relatório STRIDE
5. Baixe o PDF
        """)

        st.divider()
        st.markdown("**Metodologia STRIDE:**")
        stride_info = {
            "S": "Spoofing", "T": "Tampering", "R": "Repudiation",
            "I": "Info Disclosure", "D": "Denial of Service", "E": "Elevation of Privilege",
        }
        for k, v in stride_info.items():
            bg = STRIDE_COLORS.get(k, "#F5F5F5")
            tc = STRIDE_TEXT_COLORS.get(k, "#000")
            st.markdown(
                f'<span class="stride-badge" style="background:{bg};color:{tc}">{k}</span> {v}',
                unsafe_allow_html=True,
            )

    return {
        "backend": backend,
        "api_key": api_key,
        "model_path": model_path_input,
        "confidence": confidence,
        "selected_model": selected_model,
        "ollama_model": ollama_model,
        "ollama_url": ollama_url,
        "openai_base_url": openai_base_url,
        "use_vision": use_vision,
    }


def render_component_detections(detection_result, annotated_image_np):
    st.markdown("### Detected Components")
    col_img, col_info = st.columns([2, 1])

    with col_img:
        rgb = cv2.cvtColor(annotated_image_np, cv2.COLOR_BGR2RGB)
        st.image(rgb, caption="Architecture diagram with detected components", use_container_width=True)

    with col_info:
        counts = detection_result.component_counts
        st.markdown(f"**{len(detection_result.detections)} components detected**")
        st.markdown(f"**{len(counts)} unique types**")
        st.divider()
        for ctype, count in sorted(counts.items()):
            label = ctype.replace("_", " ").title()
            st.markdown(f"- **{label}** × {count}")

        if detection_result.detections:
            st.divider()
            st.markdown("**Confidence scores:**")
            for det in detection_result.detections:
                conf_pct = int(det.confidence * 100)
                label = det.class_name.replace("_", " ").title()
                st.progress(conf_pct / 100, text=f"{label}: {conf_pct}%")


def render_stride_matrix(analysis: dict):
    st.markdown("### STRIDE Threat Matrix")
    stride_summary = analysis.get("stride_summary", {})
    severity_counts = analysis.get("severity_counts", {})

    # risk overview
    risk = analysis.get("risk_level", "Unknown")
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Overall Risk", risk)
    with col2:
        st.metric("🔴 Critical", severity_counts.get("Critical", 0))
    with col3:
        st.metric("🟠 High", severity_counts.get("High", 0))
    with col4:
        st.metric("🟡 Medium", severity_counts.get("Medium", 0))
    with col5:
        st.metric("🟢 Low", severity_counts.get("Low", 0))

    st.divider()

    full_names = {
        "S": "Spoofing", "T": "Tampering", "R": "Repudiation",
        "I": "Information Disclosure", "D": "Denial of Service", "E": "Elevation of Privilege",
    }

    for cat, threats in stride_summary.items():
        if not threats:
            continue
        bg = STRIDE_COLORS.get(cat, "#F5F5F5")
        tc = STRIDE_TEXT_COLORS.get(cat, "#000")
        with st.expander(
            f"{cat} — {full_names.get(cat, cat)} ({len(threats)} threat(s))", expanded=False
        ):
            for t in threats:
                st.markdown(f"- {t}")


def render_threats_by_component(analysis: dict):
    st.markdown("### Detailed Threat Analysis")
    threats_by_component = analysis.get("threats_by_component", {})

    for comp, threats in threats_by_component.items():
        comp_label = comp.replace("_", " ").title()
        with st.expander(f"**{comp_label}** — {len(threats)} threats", expanded=False):
            for t in threats:
                cat = t["stride_category"]
                sev = t["severity"]
                bg = STRIDE_COLORS.get(cat, "#F5F5F5")
                tc = STRIDE_TEXT_COLORS.get(cat, "#000")

                st.markdown(
                    f'<div class="threat-card">'
                    f'<span class="stride-badge" style="background:{bg};color:{tc}">{cat}</span>'
                    f' &nbsp; {SEV_BADGE.get(sev, sev)}'
                    f'<br><strong>{t["threat_name"]}</strong>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
                st.markdown(t["description"])
                st.markdown("**Countermeasures:**")
                for cm in t.get("countermeasures", []):
                    st.markdown(f"  - {cm}")
                if t.get("cwe_ids"):
                    st.markdown(f"*CWEs: {', '.join(t['cwe_ids'])}*")
                st.divider()


def render_ai_analysis(analysis: dict):
    st.markdown("### AI-Generated Analysis")

    ai_text = analysis.get("ai_analysis", "")
    if ai_text:
        st.markdown(ai_text)

    # component-level analyses
    comp_analyses = analysis.get("component_analyses", [])
    if comp_analyses:
        st.markdown("#### Per-Component STRIDE Breakdown")
        for ca in comp_analyses:
            comp = ca.get("component", "").replace("_", " ").title()
            with st.expander(f"{comp}", expanded=False):
                if ca.get("trust_boundary"):
                    st.info(f"Trust boundary: {ca['trust_boundary']}")
                stride_threats = ca.get("stride_threats", {})
                full_names = {
                    "S": "Spoofing", "T": "Tampering", "R": "Repudiation",
                    "I": "Info Disclosure", "D": "Denial of Service", "E": "Elevation of Privilege",
                }
                for cat, threat_text in stride_threats.items():
                    bg = STRIDE_COLORS.get(cat, "#F5F5F5")
                    tc = STRIDE_TEXT_COLORS.get(cat, "#000")
                    st.markdown(
                        f'<span class="stride-badge" style="background:{bg};color:{tc}">{cat} — {full_names.get(cat,"")}</span>',
                        unsafe_allow_html=True,
                    )
                    st.markdown(threat_text)
                if ca.get("highest_risk_threat"):
                    st.error(f"Highest risk: {ca['highest_risk_threat']}")

    # data flow threats
    df_threats = analysis.get("data_flow_threats", [])
    if df_threats:
        st.markdown("#### Data Flow Threats")
        import pandas as pd
        df = pd.DataFrame(df_threats)
        if not df.empty:
            st.dataframe(df, use_container_width=True)

    # recommendations
    recs = analysis.get("recommendations", [])
    if recs:
        st.markdown("#### Prioritized Recommendations")
        for r in sorted(recs, key=lambda x: x.get("priority", 99)):
            pri = r.get("priority", "")
            action = r.get("action", "")
            rationale = r.get("rationale", "")
            effort = r.get("effort", "")
            impact = r.get("impact", "")
            st.markdown(
                f"**#{pri}** {action}  \n"
                f"_{rationale}_  \n"
                f"Effort: `{effort}` · Impact: `{impact}`"
            )
            st.divider()


def render_pdf_download(analysis: dict, annotated_image_np):
    st.markdown("### Download Report")
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        tmp_path = f.name

    try:
        pdf_path = generate_report(analysis, annotated_image_np, output_path=tmp_path)
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()

        st.download_button(
            label="📥 Download PDF Report",
            data=pdf_bytes,
            file_name="stride_threat_model_report.pdf",
            mime="application/pdf",
            use_container_width=True,
        )
    except Exception as e:
        st.error(f"Failed to generate PDF: {e}")
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


# ── Main ────────────────────────────────────────────────────────────────────────

def main():
    cfg = render_sidebar()
    api_key        = cfg["api_key"]
    model_path     = cfg["model_path"]
    confidence     = cfg["confidence"]
    backend        = cfg["backend"]
    selected_model = cfg["selected_model"]
    ollama_model   = cfg["ollama_model"]
    ollama_url     = cfg["ollama_url"]
    openai_base_url= cfg["openai_base_url"]
    use_vision     = cfg.get("use_vision", False)

    st.markdown('<p class="main-title">🛡 STRIDE AI Threat Modeler</p>', unsafe_allow_html=True)
    st.markdown(
        '<p class="subtitle">Upload a software architecture diagram to automatically '
        'detect components and generate a STRIDE threat modeling report.</p>',
        unsafe_allow_html=True,
    )

    uploaded_file = st.file_uploader(
        "Upload Architecture Diagram",
        type=["png", "jpg", "jpeg", "bmp", "webp"],
        help="Supports PNG, JPEG, BMP, WebP formats",
    )

    if uploaded_file is None:
        st.info("Upload an architecture diagram image to get started.")

        st.markdown("---")
        st.markdown("#### Example architectures the system can analyze:")
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown("**AWS Multi-AZ**\nVPC · ALB · EC2 · RDS · ElastiCache · S3")
        with c2:
            st.markdown("**Azure API Management**\nEntra · API GW · Logic Apps · Azure Services")
        with c3:
            st.markdown("**Microservices**\nAPI Gateway · Services · Databases · Message Queues")
        return

    image = Image.open(uploaded_file)
    st.image(image, caption="Uploaded diagram", use_container_width=True)

    if st.button("🔍 Analyze Architecture", type="primary", use_container_width=True):
        # Validate model exists
        if not Path(model_path).exists():
            st.error(
                f"Model not found at `{model_path}`. "
                "Please run `python train.py` first to train the model."
            )
            return

        if BACKEND_INFO[backend]["needs_key"] and not api_key:
            st.error(f"Por favor, informe a {BACKEND_INFO[backend]['key_label']} na barra lateral.")
            return

        spinner_msg = ("Detectando componentes (YOLOv8 + Llama Vision)..."
                       if use_vision else "Detectando componentes com YOLOv8...")
        with st.spinner(spinner_msg):
            try:
                if use_vision:
                    detector = HybridDetector(
                        model_path=model_path, conf=confidence,
                        vision_model="llama3.2-vision",
                        ollama_url=ollama_url,
                        use_vision=True,
                    )
                else:
                    detector = ArchitectureDetector(model_path=model_path, conf=confidence)
                detection_result = detector.detect(image)
            except Exception as e:
                st.error(f"Detecção falhou: {e}")
                return

        if not detection_result.detections:
            st.warning(
                "No components detected. Try lowering the confidence threshold "
                "or ensure the model is trained on similar diagrams."
            )
            return

        st.success(f"Detected {len(detection_result.detections)} components!")

        tab1, tab2, tab3, tab4 = st.tabs([
            "🔎 Detections", "📊 STRIDE Matrix", "🔐 Threat Details", "🤖 AI Analysis"
        ])

        with tab1:
            render_component_detections(detection_result, detection_result.annotated_image)

        backend_label = BACKEND_INFO[backend]["label"]
        with st.spinner(f"Rodando análise STRIDE com {backend_label}..."):
            try:
                analyzer = StrideAnalyzer(
                    backend=backend,
                    api_key=api_key or None,
                    model=selected_model or None,
                    ollama_model=ollama_model,
                    ollama_url=ollama_url,
                    openai_base_url=openai_base_url,
                )
                analysis = analyzer.analyze(detection_result)
            except Exception as e:
                st.error(f"Análise STRIDE falhou: {e}")
                return

        with tab2:
            render_stride_matrix(analysis)

        with tab3:
            render_threats_by_component(analysis)

        with tab4:
            render_ai_analysis(analysis)

        st.divider()
        render_pdf_download(analysis, detection_result.annotated_image)


if __name__ == "__main__":
    main()
