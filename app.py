# app.py — Streamlit UI wrapper for Rogue
import streamlit as st
import subprocess
import shlex
import os
import time
from pathlib import Path

st.set_page_config(page_title="Rogue UI", layout="centered")
st.title("Rogue - Web Vulnerability Scanner")

# --- Inputs ---
url = st.text_input("Target URL", "http://testphp.vulnweb.com")
plans = st.number_input("Plans per page (-p)", min_value=1, max_value=50, value=1, step=1)
iterations = st.number_input("Max iterations (-i)", min_value=1, max_value=20, value=1, step=1)
model = st.selectbox("Model (-m)", ["o4-mini", "o3-mini", "o1-preview"], index=0)
expand = st.checkbox("Expand discovered URLs (-e)", value=False)
subdomains = st.checkbox("Enumerate subdomains (-s)", value=False)
output_dir = st.text_input("Output directory (-o)", "security_results")
demo_mode = st.checkbox("DEMO_MODE (no OpenAI API calls)", value=True)
timeout_seconds = st.number_input("Timeout (seconds)", min_value=30, max_value=1800, value=300)

run_button = st.button("🚀 Start Scan")

def run_and_stream(cmd, placeholder, timeout):
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
    out_lines = []
    start = time.time()
    try:
        while True:
            line = process.stdout.readline()
            if line:
                out_lines.append(line.rstrip())
                if len(out_lines) > 800:
                    out_lines = out_lines[-800:]
                # show the last ~300 lines to the UI
                placeholder.code("\n".join(out_lines[-300:]))
            elif process.poll() is not None:
                break
            if time.time() - start > timeout:
                try:
                    process.kill()
                except:
                    pass
                out_lines.append(f"[!] KILLED after timeout {timeout}s")
                placeholder.code("\n".join(out_lines[-300:]))
                return process.returncode or -1, "\n".join(out_lines)
        return process.returncode, "\n".join(out_lines)
    except Exception as e:
        try:
            process.kill()
        except:
            pass
        out_lines.append(f"[!] Exception: {e}")
        placeholder.code("\n".join(out_lines[-300:]))
        return -2, "\n".join(out_lines)

if run_button:
    # ensure demo mode env var is set for the process
    if demo_mode:
        os.environ["DEMO_MODE"] = "1"
    else:
        os.environ.pop("DEMO_MODE", None)

    # If constants.py still requires OPENAI_API_KEY at import time, set a dummy one to avoid import errors
    if "OPENAI_API_KEY" not in os.environ:
        os.environ["OPENAI_API_KEY"] = "demo-key"

    st.info(f"Starting scan for: {url}")
    placeholder = st.empty()

    cmd = ["python", "run.py", "-u", url, "-p", str(plans), "-i", str(iterations), "-m", model, "-o", output_dir]
    if expand:
        cmd.append("-e")
    if subdomains:
        cmd.append("-s")

    st.write("Command:", " ".join(shlex.quote(x) for x in cmd))
    returncode, stdout_all = run_and_stream(cmd, placeholder, int(timeout_seconds))

    if returncode == 0:
        st.success("✅ Scan completed (process exit 0).")
    elif returncode > 0:
        st.warning(f"⚠️ Scan finished with return code {returncode}. Check logs above.")
    else:
        st.error(f"❌ Scan failed with return code {returncode}.")

   # safe file listing / preview (replace the existing block)
outp = Path(output_dir)
if outp.exists():
    files = sorted(list(outp.rglob("*")), key=lambda f: f.stat().st_mtime, reverse=True)
    if files:
        st.markdown("### 📂 Generated files (most recent first)")
        for f in files[:50]:
            try:
                display_path = f.relative_to(Path.cwd())
            except Exception:
                display_path = f  # fallback to absolute path
            st.write(f"- {display_path} — {f.stat().st_size} bytes")
        # preview the most recent .md or .txt
        recent = next((f for f in files if f.suffix.lower() in (".md", ".txt")), None)
        if recent:
            try:
                st.markdown("---")
                st.write(f"### Preview of `{recent.name}`")
                st.code(recent.read_text(encoding="utf-8")[:20000])
                with open(recent, "rb") as fh:
                    st.download_button("Download latest report", fh.read(), file_name=recent.name)
            except Exception as e:
                st.write("Could not preview file:", e)
    else:
        st.write("No files produced in output directory yet.")
else:
    st.write("Output directory does not exist:", output_dir)

