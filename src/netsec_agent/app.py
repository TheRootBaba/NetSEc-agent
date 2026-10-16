

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from pathlib import Path
from typing import Any

import streamlit as st
from dotenv import load_dotenv

from netsec_agent.authorization import ALLOWED_SCAN_TYPES, AssessmentScope
from netsec_agent.graph import run_agent

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

APP_NAME = "NetSec Agent"
MAX_SUBNET_ADDRESSES = 256

TARGET_PATTERN = re.compile(
    r"(?<![\w.])"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"(?:/\d{1,2})?"
    r"(?![\w.])"
)

st.set_page_config(
    page_title="NetSec Agent | Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# Styling

st.markdown(
    """
    <style>
    :root {
        --ns-bg: #0b1020;
        --ns-panel: #111a2d;
        --ns-border: #26334b;
        --ns-text: #edf3ff;
        --ns-muted: #9aaac3;
        --ns-accent: #60a5fa;
        --ns-green: #34d399;
    }

    .stApp {
        background:
            radial-gradient(ellipse at 20% 0%, #172544 0%, transparent 42%),
            var(--ns-bg);
        color: var(--ns-text);
        font-family: 'DM Sans', sans-serif;
    }

    h1, h2, h3, h4 {
        font-family: 'Space Grotesk', sans-serif !important;
        letter-spacing: -0.035em;
    }

    [data-testid="stSidebar"] {
        background: #0a0f1c;
        border-right: 1px solid var(--ns-border);
    }

    [data-testid="stSidebar"] * {
        font-family: 'DM Sans', sans-serif;
    }

    .ns-brand {
        display: flex;
        align-items: center;
        gap: 12px;
        margin: 8px 0 28px;
    }

    .ns-brand-icon {
        width: 45px;
        height: 45px;
        display: flex;
        align-items: center;
        justify-content: center;
        border: 1px solid #345178;
        border-radius: 14px;
        background: linear-gradient(135deg, #1e3a5f, #122238);
        font-size: 23px;
    }

    .ns-brand-name {
        color: #f3f7ff;
        font-size: 20px;
        font-weight: 700;
        font-family: 'Space Grotesk', sans-serif;
    }

    .ns-brand-sub {
        color: var(--ns-muted);
        font-size: 11px;
        letter-spacing: .11em;
        text-transform: uppercase;
    }

    .ns-eyebrow {
        color: var(--ns-accent);
        font-size: 11px;
        font-weight: 700;
        letter-spacing: .15em;
        text-transform: uppercase;
        margin-bottom: 10px;
    }

    .ns-hero {
        padding: 24px 0 16px;
    }

    .ns-hero h1 {
        font-size: clamp(32px, 4vw, 48px);
        line-height: 1.08;
        margin: 0 0 12px;
        color: #f4f7ff;
    }

    .ns-hero p {
        color: var(--ns-muted);
        max-width: 720px;
        font-size: 15px;
        line-height: 1.7;
    }

    .ns-card {
        border: 1px solid var(--ns-border);
        border-radius: 16px;
        background: rgba(17, 26, 45, .84);
        padding: 18px 20px;
        min-height: 115px;
    }

    .ns-card-label {
        color: var(--ns-muted);
        font-size: 12px;
        margin-bottom: 10px;
    }

    .ns-card-value {
        color: #f2f6ff;
        font-family: 'Space Grotesk', sans-serif;
        font-size: 20px;
        font-weight: 600;
    }

    .ns-card-detail {
        color: var(--ns-muted);
        font-size: 12px;
        margin-top: 8px;
    }

    .ns-section-title {
        font-family: 'Space Grotesk', sans-serif;
        color: #edf3ff;
        font-size: 20px;
        font-weight: 600;
        margin: 18px 0 4px;
    }

    .ns-section-subtitle {
        color: var(--ns-muted);
        font-size: 13px;
        margin-bottom: 16px;
    }

    .ns-notice {
        background: rgba(96, 165, 250, .08);
        border: 1px solid rgba(96, 165, 250, .26);
        padding: 14px 16px;
        border-radius: 12px;
        color: #d8e7ff;
        font-size: 13px;
        line-height: 1.65;
    }

    .ns-footer {
        color: #7f91ad;
        font-size: 11px;
        border-top: 1px solid var(--ns-border);
        margin-top: 30px;
        padding-top: 16px;
    }

    [data-testid="stChatMessage"] {
        border: 1px solid rgba(88, 109, 145, .22);
        border-radius: 16px;
        background: rgba(17, 26, 45, .58);
        padding: 14px 16px;
    }

    [data-testid="stChatInput"] {
        border-color: #354561 !important;
    }

    .stButton > button {
        border-radius: 10px;
        min-height: 42px;
        font-weight: 600;
        transition: all .15s ease;
    }

    .stButton > button[kind="primary"] {
        background: #2563eb;
        border: 1px solid #3b82f6;
        color: white;
    }

    .stButton > button[kind="primary"]:hover {
        background: #1d4ed8;
        border-color: #60a5fa;
    }

    [data-testid="stMetric"] {
        background: rgba(17, 26, 45, .72);
        border: 1px solid var(--ns-border);
        border-radius: 14px;
        padding: 16px;
    }

    code {
        color: #93c5fd !important;
    }

    hr {
        border-color: var(--ns-border) !important;
    }

    @media (max-width: 700px) {
        .ns-hero h1 { font-size: 32px; }
        .ns-card { min-height: 95px; }
    }

    /* Refined workspace layout */
    .stApp {
        background:
            radial-gradient(ellipse at 12% 0%, rgba(37, 99, 235, .13), transparent 38%),
            var(--ns-bg);
        font-family: "Segoe UI", "Inter", sans-serif;
    }

    h1, h2, h3, h4,
    .ns-brand-name, .ns-hero h1, .ns-card-value {
        font-family: "Segoe UI", "Inter", sans-serif !important;
        letter-spacing: -0.025em;
    }

    .block-container {
        max-width: 1440px;
        padding-top: 1.4rem;
        padding-bottom: 2.5rem;
    }

    .ns-brand { margin-bottom: 22px; }
    .ns-brand-icon {
        box-shadow: 0 8px 24px rgba(37, 99, 235, .13);
    }

    .ns-hero {
        padding: 12px 0 8px;
    }

    .ns-hero h1 {
        font-size: clamp(30px, 3.2vw, 42px);
        line-height: 1.12;
        margin-bottom: 10px;
    }

    .ns-hero p {
        max-width: 760px;
        font-size: 14px;
        line-height: 1.65;
    }

    .ns-card {
        min-height: 104px;
        padding: 17px 18px;
        background: linear-gradient(145deg, rgba(20, 31, 52, .96), rgba(15, 23, 39, .92));
        box-shadow: 0 8px 24px rgba(0, 0, 0, .08);
        transition: border-color .15s ease, transform .15s ease;
    }

    .ns-card:hover { border-color: #3b5275; }
    .ns-card-label { letter-spacing: .07em; font-weight: 600; }
    .ns-card-value { font-size: 19px; overflow-wrap: anywhere; }
    .ns-card-detail { line-height: 1.45; }

    .ns-section-title {
        font-size: 19px;
        margin-top: 25px;
    }

    .ns-section-subtitle {
        line-height: 1.55;
        margin-bottom: 12px;
    }

    .ns-notice {
        line-height: 1.75;
        background: rgba(96, 165, 250, .055);
    }

    [data-testid="stChatMessage"] {
        border: 1px solid rgba(110, 135, 175, .18);
        border-radius: 15px;
        padding: 15px 17px;
        margin-bottom: 12px;
        background: rgba(17, 26, 45, .48);
    }

    [data-testid="stChatMessage"] p {
        line-height: 1.7;
    }

    [data-testid="stChatInput"] {
        border: 1px solid #354561 !important;
        border-radius: 14px !important;
        background: #111a2d !important;
    }

    [data-testid="stChatInput"]:focus-within {
        border-color: #60a5fa !important;
        box-shadow: 0 0 0 1px rgba(96, 165, 250, .2);
    }

    .stButton > button {
        border-radius: 11px;
        min-height: 42px;
        font-weight: 600;
        line-height: 1.35;
        white-space: normal;
    }

    [data-testid="stSidebar"] .stButton > button {
        text-align: left;
        padding: .55rem .75rem;
        border-color: rgba(100, 125, 165, .22);
        background: rgba(17, 26, 45, .55);
    }

    [data-testid="stSidebar"] .stButton > button:hover {
        border-color: #49648b;
        background: rgba(37, 99, 235, .12);
    }

    [data-testid="stMetric"] {
        background: rgba(17, 26, 45, .72);
        border: 1px solid var(--ns-border);
        border-radius: 14px;
        padding: 15px;
    }

    .ns-footer { line-height: 1.8; }

    @media (max-width: 700px) {
        .block-container {
            padding-top: .8rem;
            padding-left: 1rem;
            padding-right: 1rem;
        }
        .ns-hero h1 { font-size: 30px; }
        .ns-card { min-height: 90px; padding: 14px; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# Validation and agent helpers

def _extract_target(message: str) -> str | None:
    """Extract the first IPv4 address or IPv4 CIDR target."""
    match = TARGET_PATTERN.search(message)
    if match is None:
        return None

    candidate = match.group(0)

    try:
        if "/" in candidate:
            network = ipaddress.ip_network(candidate, strict=True)
            if not isinstance(network, ipaddress.IPv4Network):
                return None
            return str(network)

        address = ipaddress.ip_address(candidate)
        if not isinstance(address, ipaddress.IPv4Address):
            return None
        return str(address)

    except ValueError:
        return None


def _validate_target(target: str) -> str:
    """Validate a single IPv4 host or a small private IPv4 subnet."""
    candidate = target.strip()

    try:
        if "/" in candidate:
            network = ipaddress.ip_network(candidate, strict=True)

            if not isinstance(network, ipaddress.IPv4Network):
                raise ValueError("Only IPv4 subnets are supported.")

            if not network.is_private:
                raise ValueError(
                    "Subnet discovery is limited to private IPv4 networks."
                )

            if network.prefixlen == 32:
                raise ValueError(
                    "Enter a subnet range rather than a /32 host."
                )

            if network.num_addresses > MAX_SUBNET_ADDRESSES:
                raise ValueError(
                    f"Subnet discovery is limited to "
                    f"{MAX_SUBNET_ADDRESSES} addresses per request."
                )

            return str(network)

        address = ipaddress.ip_address(candidate)

        if not isinstance(address, ipaddress.IPv4Address):
            raise TypeError("Only IPv4 targets are currently supported.")

        if (
            address.is_unspecified
            or address.is_multicast
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
        ):
            raise ValueError(
                "This address is not supported as a remote assessment target."
            )

        return str(address)

    except ValueError as exc:
        raise ValueError(str(exc)) from exc


def _is_assessment_request(message: str) -> bool:
    """Recognize scan requests and standalone IP/CIDR follow-ups."""
    if _extract_target(message) is not None:
        return True

    keywords = (
        "scan",
        "nmap",
        "port",
        "network discovery",
        "discover hosts",
        "service detection",
        "operating system",
        "os detection",
        "assess my network",
        "security assessment",
        "find open ports",
    )

    normalized = message.casefold()
    return any(keyword in normalized for keyword in keywords)


def _build_scope(target: str) -> AssessmentScope:
    """Build an explicit one-target scope after user confirmation."""
    return AssessmentScope(
        authorized=True,
        approved_targets=(target,),
        max_targets=1,
        allowed_scan_types=ALLOWED_SCAN_TYPES,
    )


def _run_async(coroutine: Any) -> Any:
    """Run an async agent operation from Streamlit's synchronous flow."""
    return asyncio.run(coroutine)


def _response_text(result: Any) -> str:
    """Extract a readable response from common LangGraph result shapes."""
    if isinstance(result, str):
        return result

    if not isinstance(result, dict):
        return str(result)

    for key in ("response", "output", "answer", "final"):
        value = result.get(key)
        if isinstance(value, str) and value.strip():
            return value

    messages = result.get("messages", [])

    for message in reversed(messages):
        if getattr(message, "type", None) == "ai":
            content = getattr(message, "content", "")
            if isinstance(content, str) and content.strip():
                return content
            if isinstance(content, list):
                parts = [
                    item.get("text", "")
                    for item in content
                    if isinstance(item, dict)
                    and isinstance(item.get("text"), str)
                ]
                combined = "\n".join(parts).strip()
                if combined:
                    return combined

    return "The agent completed without returning a readable response."


def _format_agent_response(text: str) -> str:
    """Convert common HTML formatting in model output to Markdown."""
    import html
    import re

    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<\s*li\s*>", "\n- ", text, flags=re.IGNORECASE)
    text = re.sub(r"</\s*li\s*>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</?\s*(?:ul|ol)\s*>", "\n", text, flags=re.IGNORECASE)
    text = html.unescape(text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _is_successful_assessment_response(text: str) -> bool:
    """Exclude known failure messages from the assessment counter."""
    failures = (
        "The request failed.",
        "Assessment not started:",
        "Assessment cancelled.",
        "I couldn't safely process that follow-up",
    )
    return bool(text.strip()) and not text.startswith(failures)


def _ask_agent(
    message: str,
    history: list[dict[str, str]],
    scope: AssessmentScope | None = None,
) -> str:
    """Call the LangGraph agent and convert errors to a safe UI message."""
    try:
        result = _run_async(
            run_agent(
                message,
                history=history,
                scope=scope,
            )
        )
        return _response_text(result)

    except Exception:
        logger.exception("Agent request failed")
        return (
            "The request failed. Check the Streamlit terminal for the full "
            "error. Verify your Groq configuration, MCP server, and Nmap "
            "installation. No successful assessment result was returned."
        )


def _is_subnet(target: str) -> bool:
    return "/" in target


def _initialize_state() -> None:
    if "messages" not in st.session_state:
        st.session_state.messages = [
            {
                "role": "assistant",
                "content": (
                    "Welcome to NetSec Agent. I can help you understand your "
                    "network, discover live hosts, inspect TCP ports, and "
                    "review service information from authorized assessments.\n\n"
                    "Tell me what you want to investigate, or enter an IP "
                    "address to start."
                ),
            }
        ]

    if "pending_assessment" not in st.session_state:
        st.session_state.pending_assessment = None

    if "assessment_count" not in st.session_state:
        st.session_state.assessment_count = 0


_initialize_state()


# Sidebar

with st.sidebar:
    st.markdown(
        """
        <div class="ns-brand">
          <div class="ns-brand-icon">🛡️</div>
          <div>
            <div class="ns-brand-name">NetSec Agent</div>
            <div class="ns-brand-sub">Security operations</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### Workspace")
    st.caption("AI-assisted network visibility")

    st.markdown("---")
    st.markdown("#### Assessment scope")

    st.caption(
        "Only assess systems you own or have explicit permission to test. "
        "A scan is not started until you confirm the target."
    )

    st.markdown(
        """
        <div class="ns-notice">
          <strong>Scope controls enabled</strong><br>
          • Explicit confirmation before scans<br>
          • One host or approved subnet per request<br>
          • Private subnet discovery limited to 256 addresses<br>
          • No fabricated scan findings
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("---")
    st.markdown("#### Quick prompts")

    quick_prompts = [
        "Explain what open ports mean.",
        "How can I harden a Windows host?",
        "What evidence should a network report include?",
        "Help me understand service version detection.",
    ]

    for index, prompt in enumerate(quick_prompts):
        if st.button(
            prompt,
            key=f"quick_prompt_{index}",
            use_container_width=True,
        ):
            st.session_state.quick_prompt = prompt
            st.rerun()

    st.markdown("---")

    if st.button("＋ New conversation", use_container_width=True):
        st.session_state.messages = [
            {
                "role": "assistant",
                "content": (
                    "New conversation started. What would you like to "
                    "investigate?"
                ),
            }
        ]
        st.session_state.pending_assessment = None
        st.session_state.quick_prompt = ""
        st.rerun()

    st.markdown(
        """
        <div class="ns-footer">
          NETSEC AGENT · LOCAL WORKSPACE<br>
          Evidence first. Authorization always.
        </div>
        """,
        unsafe_allow_html=True,
    )


# Main header and dashboard

st.markdown(
    """
    <div class="ns-hero">
      <div class="ns-eyebrow">Network intelligence · AI assistant</div>
      <h1>See your network<br>more clearly.</h1>
      <p>
        Investigate hosts, inspect exposed services, and turn observed
        scan output into practical security guidance. Results depend on
        the configured tools and the evidence they actually return.
      </p>
    </div>
    """,
    unsafe_allow_html=True,
)

metric_columns = st.columns(3)

metric_cards = [
    ("WORKSPACE", "Security assistant", "Conversational investigation"),
    ("SUCCESSFUL RUNS", str(st.session_state.assessment_count), "Agent runs without a reported workflow error"),
    ("SCOPE", "Confirmation required", "Assessment starts only after confirmation"),
]

for column, (label, value, detail) in zip(metric_columns, metric_cards):
    with column:
        st.markdown(
            f"""
            <div class="ns-card">
              <div class="ns-card-label">{label}</div>
              <div class="ns-card-value">{value}</div>
              <div class="ns-card-detail">{detail}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

st.markdown(
    '<div class="ns-section-title">Security assistant</div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="ns-section-subtitle">'
    'Ask a question or start an explicitly authorized assessment.'
    '</div>',
    unsafe_allow_html=True,
)


# Conversation history

for message in st.session_state.messages:
    with st.chat_message(
        message["role"],
        avatar="🛡️" if message["role"] == "assistant" else "👤",
    ):
        st.markdown(message["content"])


# Pending scan authorization

pending = st.session_state.pending_assessment

if pending:
    target = pending["target"]

    st.markdown("---")
    st.markdown("### Confirm assessment")
    st.warning(
        f"Target: `{target}`\n\n"
        "Confirm only if you own this system or have explicit permission "
        "to assess it. The tool configuration and scope validation still "
        "apply."
    )

    if _is_subnet(target):
        st.info(
            "This is a subnet-discovery request. Discovery is limited to "
            "private IPv4 ranges containing at most 256 addresses."
        )
    else:
        st.info(
            "The agent will select from the assessment tools configured "
            "for this workspace. Port and service results may vary with "
            "permissions, network filtering, and tool configuration."
        )

    confirm_column, cancel_column = st.columns(2)

    with confirm_column:
        confirm = st.button(
            "Confirm authorized assessment",
            type="primary",
            use_container_width=True,
            key="confirm_assessment",
        )

    with cancel_column:
        cancel = st.button(
            "Cancel",
            use_container_width=True,
            key="cancel_assessment",
        )

    if cancel:
        st.session_state.pending_assessment = None
        st.session_state.messages.append(
            {
                "role": "assistant",
                "content": "Assessment cancelled. No scan was requested.",
            }
        )
        st.rerun()

    if confirm:
        st.session_state.pending_assessment = None

        with st.chat_message("assistant", avatar="🛡️"), st.status(
            f"Assessing {target}…",
            expanded=True,
        ) as status:
            st.write("Validating the requested target and scope.")

            try:
                validated_target = _validate_target(target)
                scope = _build_scope(validated_target)

                st.write("Loading the configured assessment tools.")
                prompt = (
                    "Perform an authorized network assessment of "
                    f"{validated_target}. Use only the tools actually "
                    "provided to you. For a host, inspect accessible "
                    "TCP ports and service information as supported by "
                    "the configured tools. For a subnet, perform host "
                    "discovery only if a matching configured tool is "
                    "available. Report observed evidence separately "
                    "from interpretations. Do not invent port states, "
                    "service versions, operating systems, or CVEs. "
                    "State limitations and unsupported checks clearly."
                )

                previous_history = [
                    {
                        "role": item["role"],
                        "content": item["content"],
                    }
                    for item in st.session_state.messages
                    if item["role"] in ("user", "assistant")
                ]

                st.write("Running the agent workflow.")
                answer = _ask_agent(
                    prompt,
                    previous_history,
                    scope=scope,
                )

                workflow_failed = answer.startswith("The request failed.")

                status.update(
                    label=(
                        "Assessment workflow failed"
                        if workflow_failed
                        else "Agent workflow returned a response"
                    ),
                    state="error" if workflow_failed else "complete",
                    expanded=workflow_failed,
                )

                st.markdown(_format_agent_response(answer))

                st.session_state.messages.append(
                    {
                        "role": "assistant",
                        "content": answer,
                    }
                )
                if (
                    not workflow_failed
                    and _is_successful_assessment_response(answer)
                ):
                    st.session_state.assessment_count += 1

            except (ValueError, TypeError, PermissionError) as exc:
                status.update(
                    label="Assessment could not start",
                    state="error",
                )
                error_message = f"Assessment not started: {exc}"
                st.error(error_message)
                st.session_state.messages.append(
                    {
                        "role": "assistant",
                        "content": error_message,
                    }
                )

        st.rerun()


# Chat input

chat_placeholder = (
    "Ask about your network, ports, services, or defensive controls…"
)

quick_prompt = st.session_state.pop("quick_prompt", "")

if quick_prompt:
    user_input = quick_prompt
else:
    user_input = st.chat_input(chat_placeholder)

if user_input:
    st.session_state.messages.append(
        {"role": "user", "content": user_input}
    )

    normalized_input = user_input.strip().casefold()
    if normalized_input in {
        "i approve", "approved", "i approve it", "yes", "yes please",
        "sure", "ok", "okay", "go ahead", "do it",
    }:
        answer = (
            "Approval noted, but no scan was started from this message. "
            "Enter the target and request the specific assessment, then "
            "use the **Confirm authorized assessment** button."
        )
        with st.chat_message("assistant", avatar="assistant"):
            st.markdown(answer)
        st.session_state.messages.append(
            {"role": "assistant", "content": answer}
        )
        st.rerun()

    target = _extract_target(user_input)

    if target is not None and _is_assessment_request(user_input):
        try:
            validated_target = _validate_target(target)
            st.session_state.pending_assessment = {
                "target": validated_target,
            }
        except (ValueError, TypeError) as exc:
            st.session_state.messages.append(
                {
                    "role": "assistant",
                    "content": f"Target validation failed: {exc}",
                }
            )

        st.rerun()

    with st.chat_message("assistant", avatar="🛡️"):
        with st.spinner("Thinking…"):
            history = [
                {
                    "role": item["role"],
                    "content": item["content"],
                }
                for item in st.session_state.messages[:-1]
            ]

            answer = _ask_agent(
                user_input,
                history,
                scope=None,
            )

        st.markdown(_format_agent_response(answer))

    st.session_state.messages.append(
        {"role": "assistant", "content": answer}
    )
    st.rerun()
