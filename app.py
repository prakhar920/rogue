# app.py — Streamlit UI wrapper for Rogue
import streamlit as st
import subprocess
import shlex
import os
import time
from pathlib import Path
from fpdf import FPDF

# --- Helper function to create PDF ---
def create_pdf_from_text(text: str) -> bytes:
    """Creates a PDF file in memory from a string of text."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=11)
    # We need to encode the text to latin-1 for FPDF compatibility with special characters
    pdf.multi_cell(0, 5, text.encode('latin-1', 'replace').decode('latin-1'))
    # Explicitly convert the bytearray from .output() to bytes for Streamlit
    return bytes(pdf.output())

# --- Page Configuration ---
st.set_page_config(page_title="Rogue UI", layout="wide", initial_sidebar_state="expanded")
st.title("🎯 Rogue - AI-Powered Web Vulnerability Scanner")
st.markdown("An intelligent web vulnerability scanner agent powered by Large Language Models.")

# --- Sidebar for Scan Configuration ---
with st.sidebar:
    st.header("Scan Configuration")
    
    url = st.text_input("Target URL", "http://testphp.vulnweb.com", help="The full URL to start the scan from.")
    
    model = st.selectbox(
        "LLM Model (-m)", 
        ["o4-mini", "gemini-1.5-flash", "gemini-1.5-pro", "o3-mini"], 
        index=0,
        help="Select the AI model. Gemini models require a GEMINI_API_KEY."
    )

    col1, col2 = st.columns(2)
    with col1:
        plans = st.number_input("Plans/Page (-p)", min_value=-1, value=3, step=1, help="-1 for unlimited plans.")
    with col2:
        iterations = st.number_input("Max Iterations (-i)", min_value=1, value=5, step=1, help="Max steps per plan.")

    st.subheader("Scope & Discovery")
    expand = st.checkbox("Expand Discovered URLs (-e)", value=False)
    subdomains = st.checkbox("Enumerate Subdomains (-s)", value=False)
    
    st.subheader("Advanced")
    output_dir = st.text_input("Output Directory (-o)", "security_results")
    timeout_seconds = st.number_input("Timeout (seconds)", min_value=60, value=600)
    demo_mode = st.checkbox("DEMO MODE (no API calls)", value=False, help="Uses placeholder data instead of calling LLM APIs.")
    
    run_button = st.button("🚀 Start Scan", use_container_width=True)

# --- Main Panel for Output and Reports ---
st.header("Scan Output")
placeholder = st.empty()
placeholder.code("Scan output will appear here in real-time...")

def run_and_stream(cmd, timeout):
    """Executes a command and streams its output to the Streamlit UI."""
    
    # --- THIS IS THE FIX ---
    # Force the subprocess environment to use UTF-8
    # This stops the banner from crashing on Windows
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    
    process = subprocess.Popen(
        cmd, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.STDOUT, 
        text=True, 
        bufsize=1,
        encoding='utf-8',  # Force UTF-8 encoding
        errors='replace',  # Replace any characters that can't be decoded
        env=env            # Pass the modified environment
    )
    # --- END FIX ---

    output_lines = []
    start_time = time.time()
    
    while True:
        line = process.stdout.readline()
        if line:
            output_lines.append(line.strip())
            # Display the last 50 lines to keep the UI snappy
            placeholder.code("\n".join(output_lines[-50:]))
        
        # Check for process completion
        if process.poll() is not None and not line:
            break
            
        # Check for timeout
        if time.time() - start_time > timeout:
            process.kill()
            output_lines.append(f"\n[!] TIMEOUT: Process terminated after {timeout} seconds.")
            placeholder.code("\n".join(output_lines[-50:]))
            return -1, "\n".join(output_lines)
            
    return process.returncode, "\n".join(output_lines)

if run_button:
    # Set environment variable for demo mode
    if demo_mode:
        os.environ["DEMO_MODE"] = "1"
    elif "DEMO_MODE" in os.environ:
        del os.environ["DEMO_MODE"]

    # Construct the command
    cmd = ["python", "run.py", "-u", url, "-m", model, "-p", str(plans), "-i", str(iterations), "-o", output_dir]
    if expand: cmd.append("-e")
    if subdomains: cmd.append("-s")

    st.info(f"Executing command: `{' '.join(shlex.quote(c) for c in cmd)}`")
    
    return_code, full_output = run_and_stream(cmd, int(timeout_seconds))

    if return_code == 0:
        st.success("✅ Scan completed successfully.")
    else:
        st.error(f"❌ Scan failed or was terminated (Exit Code: {return_code}). Check the output above for details.")

# --- Display Reports ---
st.header("📂 Scan Reports")
output_path = Path(output_dir)
if output_path.exists() and output_path.is_dir():
    report_files = sorted(
        [f for f in output_path.rglob('*') if f.is_file() and f.suffix.lower() in ('.md', '.txt', '.json')],
        key=lambda f: f.stat().st_mtime, 
        reverse=True
    )
    
if not report_files:
    st.write("No report files found in the output directory yet.")
else:
    latest_report = report_files[0]
    st.subheader(f"Preview of Latest Report: `{latest_report.name}`")
    
    try:
        report_content = latest_report.read_text(encoding='utf-8')

        # --- Display report content nicely in Streamlit ---
        st.markdown("### 🧾 Report Content Preview")
        st.code(report_content[:5000], language="markdown")  # limit preview to avoid UI lag

        # --- PDF Download Button Logic ---
        pdf_bytes = create_pdf_from_text(report_content)
        pdf_filename = Path(latest_report.name).with_suffix('.pdf').name

        st.download_button(
            label=f"📄 Download {pdf_filename}",
            data=pdf_bytes,
            file_name=pdf_filename,
            mime='application/pdf'
        )

    except Exception as e:
        st.error(f"Could not read or convert report file: {e}")
