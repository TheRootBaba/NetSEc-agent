"""Chat-first Streamlit interface for NetSec Agent."""

import asyncio
import ipaddress
import logging
import re

import streamlit as st

from netsec_agent.authorization import AssessmentScope
from netsec_agent.graph import run_agent
from netsec_agent.routing import is_scan_request
from netsec_agent.scope import validate_target

logger = logging.getLogger(__name__)

st.set_page_config(
    page_title="NetSec Agent",
    page_icon="🛡️",
    layout="wide",
)

st.title("NetSec Agent")
st.caption(
    "An agent that answers security questions, selects tools, "
    "runs assessments, and explains evidence."
)

if "chat_messages" not in st.session_state:
    st.session_state.chat_messages = []


def run_async(coroutine):
    """Run an asynchronous agent request from Streamlit."""
    return asyncio.run(coroutine)


def extract_ip_address(message: str) -> str | None:
    """Find and validate an IP address explicitly included in a message."""
    candidates = re.findall(
        r"(?<![0-9A-Fa-f:.])[0-9A-Fa-f:.]+(?![0-9A-Fa-f:.])",
        message,
    )

    for candidate in candidates:
        try:
            return validate_target(candidate)
        except (TypeError, ValueError):
            continue

    return None


def select_scan_type(message: str) -> str:
    """Choose a supported fixed scan profile from the user's request."""
    text = message.lower()

    discovery_terms = (
        "discover hosts",
        "discover devices",
        "find devices",
        "host discovery",
        "check if host is online",
        "is this host online",
    )

    if any(term in text for term in discovery_terms):
        return "host_discovery"

    return "port_scan"


def scan_instruction(message: str, target: str, scan_type: str) -> str:
    """Give the agent a concrete task and evidence requirements."""
    return (
        f"The user explicitly requested a network assessment in this message: "
        f"{message!r}\n"
        f"Run the {scan_type} assessment against the single target {target} "
        "using the available MCP tool. Do not scan any other target. "
        "Use actual tool output as evidence. Report observed results and the "
        "deterministic exposure score if the tool returns one. Do not invent "
        "open ports, services, vulnerabilities, or scan completion. "
        "If the tool fails or does not run, clearly report that."
    )


for message in st.session_state.chat_messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])


prompt = st.chat_input(
    "Ask a security question or request an assessment..."
)

if prompt:
    st.session_state.chat_messages.append(
        {"role": "user", "content": prompt}
    )

    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        if is_scan_request(prompt):
            target = extract_ip_address(prompt)

            if target is None:
                answer = (
                    "I can run a scan directly from chat. Include one IPv4 or "
                    "IPv6 address in your request, for example: "
                    "`Scan 192.168.1.10 and give me an exposure score.` "
                    "This version supports individual IP targets, not subnet "
                    "discovery or packet-capture analysis yet."
                )
                st.markdown(answer)
            else:
                address = ipaddress.ip_address(target)

                if address.is_multicast or address.is_unspecified:
                    answer = (
                        "That address cannot be used as an individual scan "
                        "target. Provide a specific host IP address."
                    )
                    st.markdown(answer)
                else:
                    scan_type = select_scan_type(prompt)
                    scope = AssessmentScope(
                        authorized=True,
                        approved_targets=(target,),
                        max_targets=1,
                        allowed_scan_types=frozenset({scan_type}),
                    )

                    with st.spinner(
                        f"Agent is running {scan_type.replace('_', ' ')} "
                        f"against {target}..."
                    ):
                        try:
                            result = run_async(
                                run_agent(
                                    scan_instruction(
                                        prompt,
                                        target,
                                        scan_type,
                                    ),
                                    scope=scope,
                                )
                            )
                            answer = result["messages"][-1].content
                            if not isinstance(answer, str):
                                answer = str(answer)

                            calls_used = result.get("tool_calls_used", 0)
                            if calls_used == 0:
                                answer = (
                                    "No assessment tool call was recorded, so "
                                    "there are no verified scan results.\n\n"
                                    + answer
                                )

                            st.markdown(answer)
                            st.caption(f"Agent tool calls: {calls_used}")

                        except (PermissionError, ValueError, RuntimeError) as exc:
                            logger.warning("Assessment failed: %s", exc)
                            answer = (
                                "The assessment could not be completed. "
                                "This is not evidence that the target is secure."
                            )
                            st.error(answer)
                            st.code(f"{type(exc).__name__}: {exc}")

                        except Exception:
                            logger.exception("Unexpected assessment error")
                            answer = (
                                "The assessment failed unexpectedly. "
                                "Check the terminal logs for details."
                            )
                            st.error(answer)

        else:
            history = st.session_state.chat_messages[:-1]
            transcript = "\n".join(
                f"{item['role'].upper()}: {item['content']}"
                for item in history[-10:]
            )

            request = (
                f"Conversation context:\n{transcript}\n\n"
                f"Current user message:\n{prompt}"
                if transcript
                else prompt
            )

            with st.spinner("Agent is thinking..."):
                try:
                    result = run_async(run_agent(request))
                    answer = result["messages"][-1].content
                    if not isinstance(answer, str):
                        answer = str(answer)

                except (ValueError, RuntimeError, PermissionError) as exc:
                    logger.warning("Chat request failed: %s", exc)
                    answer = (
                        "The request could not be completed. "
                        f"{type(exc).__name__}: {exc}"
                    )

                except Exception:
                    logger.exception("Unexpected chat error")
                    answer = (
                        "An unexpected error occurred. "
                        "Check the terminal logs for details."
                    )

            st.markdown(answer)

    st.session_state.chat_messages.append(
        {"role": "assistant", "content": answer}
    )


with st.sidebar:
    st.subheader("NetSec Agent")
    st.caption("Chat-driven network security assistant")
    if st.button("Clear conversation"):
        st.session_state.chat_messages = []
        st.rerun()

    st.markdown(
        """
        **Currently available**

        - Security Q&A
        - Single-IP host discovery
        - Single-IP TCP port assessment
        - Deterministic exposure scoring

        **Planned**

        - Bounded subnet device discovery
        - Service-version assessment
        - TShark PCAP analysis
        - Evidence-linked reports
        """
    )
