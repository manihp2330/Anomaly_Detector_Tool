# Anomaly Detector – Log Analysis Tool (NiceGUI + Python)

A modern, UI-based log analysis tool that detects anomalies in large system or Wi-Fi logs using customizable
regex patterns. Built with **Python**, **NiceGUI**, and multi-threaded parsing, this tool enables fast offline
analysis and live monitoring.

> This repository contains an **open-source-safe** version of the tool.
> All anomaly patterns included by default are generic and do **not** contain vendor-specific or NDA-covered strings.

---

## 🚀 Features

- **Live log monitoring** – stream logs and see anomalies in near real time.
- **Offline folder scanning** – recursively scan a directory of logs and aggregate anomalies.
- **Customizable anomaly patterns** – add, edit, delete, import, and export regex-based rules.
- **Draggable & resizable dialogs** – inspect full log lines and surrounding context.
- **Fast multi-threaded parsing** – suitable for large logs (100 MB+).
- **JSON export** – export anomaly tables for further analysis or pipelines.

---

## 🧩 Using Private Pattern Files (Company / Vendor Specific)

This public version ships with a small, safe `DEFAULT_ANOMALY_PATTERNS` dictionary that only contains
**generic Linux / Wi-Fi / driver** issues such as kernel panics, segmentation faults, link down events,
authentication failures, and timeouts.

If you work with **proprietary logs** (for example, internal firmware or customer logs under NDA):

1. Create a private JSON pattern file (do **not** commit this to GitHub):

   ```json
   {
     "Firmware Crash Type A": "your_vendor_specific_regex_here",
     "Custom Error Signature": "some_internal_pattern_here"
   }
   ```

2. Load it inside the tool using your own extension or import function (for example, by merging it with
   `DEFAULT_ANOMALY_PATTERNS` at startup).

3. Keep this JSON file **outside** the public repository to avoid leaking internal information.

This way, the open-source project remains clean and generic, while your local instance can still detect
very specific internal anomalies.

---

## ⚙️ Running the Tool

1. Install dependencies:

   ```bash
   pip install nicegui
   ```

2. Run the UI:

   ```bash
   python Anomaly_Detector_Tool_public.py
   ```

3. Open your browser at the URL printed in the console (usually `http://localhost:8080`).

---

## 🛡 Security & Privacy Notes

- The default patterns shipped here are **generic** and not tied to any specific vendor or product.
- Do **not** commit proprietary logs, internal trace identifiers, or NDA-protected patterns into the public repo.
- Use local/private JSON files for company-specific detection rules.

---

## 📜 License

This project is licensed under the MIT License – see the [`LICENSE`](LICENSE) file for details.
