from __future__ import annotations
from nicegui import ui
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime
import re
import os
import asyncio
import concurrent.futures
import time
import json
import uuid
from nicegui import ui
import html
from datetime import datetime
from pathlib import Path

# ============================================================
#  DEFAULT PATTERNS
# ============================================================

DEFAULT_ANOMALY_PATTERNS: Dict[str, str] = {
    # Kernel and System Crashes
    r"Kernel panic": "KERNEL_PANIC",
    r"Crashdump magic\[Collecting q6mem dump": "CRASH_DUMP",
    r"Call Trace": "CALL_TRACE",
    r"Target Asserted": "Q6_CRASH",
    r"Segmentation Fault|segfault": "SEGMENTATION_FAULT",
    r"Backtrace": "BACKTRACE",
    r"watchdog bite": "WATCHDOG_BITE",
    r"Oops": "OOPS_TRACE",

    # Memory Issues
    r"page\+allocation\s+failure": "PAGE_ALLOCATION_FAILURE",
    r"Unable to handle kernel NULL pointer dereference": "MEMORY_CORRUPTION",
    r"Unable to handle kernel paging request": "MEMORY_CORRUPTION",
    r"Out of memory: Kill process": "OUT_OF_MEMORY",
    r"ERROR:NBUF alloc failed": "LOW_MEMORY",

    # Device Reboot Loops
    r"Reboot Reason": "DEVICE_REBOOT",
    r"System restart": "DEVICE_REBOOT",
    r"Watchdog bark": "WATCHDOG_REBOOT",

    # Interface Issues
    r"Interface down": "INTERFACE_DOWN",
    r"Link is down": "INTERFACE_DOWN",
    r"carrier lost": "INTERFACE_DOWN",
    r"entered disabled state": "INTERFACE_DISABLED",

    # Authentication Failures
    r"authentication failed": "AUTH_FAILURE",
    r"Authentication timeout": "AUTH_TIMEOUT",
    r"Invalid credentials": "AUTH_INVALID_CREDS",
    r"Access denied": "AUTH_ACCESS_DENIED",

    # Network Issues
    r"Packet loss": "PACKET_LOSS",
    r"High latency": "HIGH_LATENCY",
    r"Connection timeout": "CONNECTION_TIMEOUT",
    r"No route to host": "NO_ROUTE",
    r"Network unreachable": "NETWORK_UNREACHABLE",

    # Configuration Issues
    r"Configuration mismatch": "CONFIG_MISMATCH",
    r"Invalid configuration": "CONFIG_INVALID",
    r"Configuration error": "CONFIG_ERROR",

    # PCI and Hardware Issues
    r"PCI\S+device\S+ID\S+mismatch": "PCI_DEVICE_MISMATCH",
    r"Hardware error": "HARDWARE_ERROR",

    # WiFi Specific Issues
    r"wlan_serialization_timer_handler": "WLAN_SERIALIZATION_ISSUE",
    r"mlme_connection_reset": "AGENT_DISCONNECTION",
    r"mlme_ext_vap_down": "VAP_DOWN",
    r"Received CSA": "CHANNEL_SWITCH",
    r"Steering is complete": "STEERING_ISSUE",
    r"Invalid beacon report": "BEACON_REPORT_ISSUE",

    # Resource Issues
    r"Resource manager crash": "RESOURCE_MANAGER_CRASH",
    r"hostapd_core": "HOSTAPD_CRASH",

    # RCU and Timing Issues
    r"RCU.*detected stall": "RCU_STALL",
    r"timeout waiting": "TIMEOUT",

    # Warnings
    r"CPU:\d+ WARNING": "CPU_WARNING",
}
# -----------------------------------------------------
# Anomaly detector
# -----------------------------------------------------

class AnomalyDetector:
    """Optimized anomaly detection engine with batch processing"""

    def __init__(self, patterns: Dict[str, str] = None):
        if patterns is None:
            patterns = DEFAULT_ANOMALY_PATTERNS.copy()

        self.patterns: Dict[str, str] = patterns
        self.custom_patterns: Dict[str, str] = {}
        self.compiled_patterns: Dict[re.Pattern, str] = {}

        # Cache for combined regex pattern
        self._combined_pattern: re.Pattern | None = None
        self._pattern_map: Dict[str, str] = {}

        # Lazy compilation flag - compile patterns only when needed
        self._patterns_compiled: bool = False

    def load_pattern_file(self, file_path: str) -> Tuple[bool, str]:
        """Load exception patterns from a Python file"""
        try:
            # Read the file
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Execute the file to get the exception_patterns dictionary
            local_vars: Dict[str, Any] = {}
            exec(content, {}, local_vars)

            if "exception_patterns" not in local_vars:
                return False, "File does not contain 'exception_patterns' dictionary"

            patterns = local_vars["exception_patterns"]
            if not isinstance(patterns, dict):
                return False, "'exception_patterns' must be a dictionary"

            # Merge with custom patterns
            self.custom_patterns = patterns
            self.patterns = {**DEFAULT_ANOMALY_PATTERNS, **self.custom_patterns}
            self._compile_patterns()

            return True, f"Loaded {len(patterns)} custom patterns"

        except Exception as e:
            return False, f"Error loading pattern file: {str(e)}"

    def _compile_patterns(self) -> None:
        """Compile regex patterns for faster matching with combined pattern optimization"""
        if self._patterns_compiled:
            return  # Already compiled

        compiled: Dict[re.Pattern, str] = {}
        pattern_parts: List[str] = []
        self._pattern_map = {}

        for idx, (pattern, category) in enumerate(self.patterns.items()):
            try:
                compiled_re = re.compile(pattern, re.IGNORECASE)
                compiled[compiled_re] = category

                # Create combined pattern for batch matching
                pattern_parts.append(f"(?P<g{idx}>{pattern})")
                self._pattern_map[f"g{idx}"] = category
            except re.error:
                # Skip invalid regex patterns
                continue

        self.compiled_patterns = compiled

        # Create combined pattern for faster batch matching
        if pattern_parts:
            try:
                combined = "|".join(pattern_parts)
                self._combined_pattern = re.compile(combined, re.IGNORECASE)
            except re.error:
                self._combined_pattern = None
        else:
            self._combined_pattern = None

        self._patterns_compiled = True

    def detect_anomalies(self, log_text: str) -> List[Dict[str, Any]]:
        """Optimized anomaly detection using combined regex pattern"""
        # Lazy compile patterns on first use
        if not self._patterns_compiled:
            self._compile_patterns()

        anomalies: List[Dict[str, Any]] = []
        lines = log_text.split("\n")

        # Use combined pattern for faster matching if available
        if self._combined_pattern and self._pattern_map:
            for line_num, line in enumerate(lines, start=1):
                if not line.strip():  # Skip empty lines
                    continue

                match = self._combined_pattern.search(line)
                if match:
                    # Find which group matched
                    for group_name, category in self._pattern_map.items():
                        if match.group(group_name):
                            anomalies.append({
                                "line_number": line_num,
                                "line": line.strip(),
                                "pattern": match.group(group_name),
                                "category": category,
                                "timestamp": datetime.now().isoformat(),
                            })
                            break  # Only record first match per line
        else:
            # Fallback to original method
            for line_num, line in enumerate(lines, start=1):
                if not line.strip():  # Skip empty lines
                    continue

                for pat, category in self.compiled_patterns.items():
                    if pat.search(line):
                        anomalies.append({
                            "line_number": line_num,
                            "line": line.strip(),
                            "pattern": pat.pattern,
                            "category": category,
                            "timestamp": datetime.now().isoformat(),
                        })
                        break  # Only record first match per line

        return anomalies

    def categorize_anomalies(
        self,
        anomalies: List[Dict[str, Any]],
        testplan_name: str | None = None,
        testcase_name: str | None = None,
        device_name: str | None = None,
    ) -> Dict[str, Any]:
        """Categorize anomalies by testplan, testcase, and device"""
        categorized: Dict[str, Any] = {
            "testplan": testplan_name or "Unknown",
            "testcase": testcase_name or "Unknown",
            "device": device_name or "Unknown",
            "anomalies": anomalies,
            "count": len(anomalies),
            "categories": {},
        }

        # Group by category
        for anomaly in anomalies:
            category = anomaly["category"]
            if category not in categorized["categories"]:
                categorized["categories"][category] = []
            categorized["categories"][category].append(anomaly)

        return categorized


# -----------------------------------------------------
# Global instances and app state
# -----------------------------------------------------

# Global anomaly detector instance
ANOMALY_DETECTOR = AnomalyDetector()


# Global state for the standalone app
class AppState:
    def __init__(self):
        self.live_anomaly_table = None
        self.anomaly_enabled = True
        self.show_live_anomaly = True


STATE = AppState()


def get_uploaded_content(e) -> bytes:
    """
    Robustly extract uploaded file bytes from NiceGUI upload event across versions.
    Tries multiple attributes: .content, .file, .files, .args.
    """
    # direct content on event
    if hasattr(e, "content") and e.content is not None:
        try:
            return e.content.read()
        except Exception:
            pass

    # single file attribute
    if hasattr(e, "file") and e.file is not None:
        try:
            return e.file.read()
        except Exception:
            pass

    # list of files
    if hasattr(e, "files") and e.files:
        f = e.files[0]
        try:
            if hasattr(f, "content") and f.content is not None:
                return f.content.read()
            if hasattr(f, "file") and f.file is not None:
                return f.file.read()
            if hasattr(f, "read"):
                return f.read()
        except Exception:
            pass

    # args dict fallback
    if hasattr(e, "args") and isinstance(e.args, dict):
        a = e.args

        c = a.get("content")
        if c is not None:
            try:
                return c.read()
            except Exception:
                pass

        f = a.get("file")
        if f is not None:
            try:
                return f.read()
            except Exception:
                pass

        files = a.get("files")
        if isinstance(files, list) and files:
            f = files[0]
            try:
                if hasattr(f, "read"):
                    return f.read()
            except Exception:
                pass

    raise AttributeError("Upload event does not contain file content")

# ---------------------------------------------------------
# ANOMALY PAGE
# ---------------------------------------------------------

def create_anomaly_page():
    """Create the anomaly detection page with two tabs"""

    with ui.row().classes("w-full items-center justify-between q-mb-lg"):
        with ui.column():
            ui.label("Anomaly Detection").classes("text-h4 text-weight-bold")
            ui.label("Detect and analyze anomalies in device logs").classes("text-subtitle1 text-grey-7")

    # Tabs: Live vs Offline
    with ui.tabs().classes("w-full") as tabs:
        live_tab = ui.tab("Live Anomaly", icon="sensors")
        offline_tab = ui.tab("Offline Anomaly", icon="folder_open")

    # Tab Panels
    with ui.tab_panels(tabs, value=live_tab).classes("w-full"):

        # ------------------ LIVE TAB ------------------
        with ui.tab_panel(live_tab):
            create_live_anomaly_tab()

        # ------------------ OFFLINE TAB ------------------
        with ui.tab_panel(offline_tab):
            create_offline_anomaly_tab()

# ---------------------------------------------------------------------
# Offline results table + parallel draggable dialog viewer
# ---------------------------------------------------------------------

def display_offline_results(anomalies: List[Dict[str, Any]], container: ui.column) -> None:
    """Display offline anomaly analysis results."""
    container.clear()

    if not anomalies:
        with container:
            ui.label('No anomalies detected').classes('text-grey-7')
        return

    with container:
        with ui.card().classes('w-full q-pa-md'):
            ui.label(f'Analysis Results: {len(anomalies)} Anomalies Found')\
              .classes('text-h6 text-weight-bold q-mb-md')

            # -----------------------------------------------------------------
            # Group by category
            # -----------------------------------------------------------------
            categories: Dict[str, List[Dict[str, Any]]] = {}
            for anomaly in anomalies:
                cat = anomaly.get('category') or 'Uncategorized'
                categories.setdefault(cat, []).append(anomaly)

            details_table: Optional[ui.table] = None

            # -----------------------------------------------------------------
            # Category summary with checkboxes and filtering
            # -----------------------------------------------------------------
            with ui.expansion('Category Summary', icon='category').classes('w-full q-mb-md'):
                checkboxes: Dict[str, ui.checkbox] = {}
                selected_categories = set(categories.keys())

                def apply_filter() -> None:
                    if details_table is None:
                        return
                    filtered = [
                        a for a in anomalies
                        if a.get('category') in selected_categories
                    ]
                    details_table.rows = filtered
                    details_table.update()

                # Individual category checkboxes, sorted by anomaly count
                for category, items in sorted(
                    categories.items(),
                    key=lambda x: len(x[1]),
                    reverse=True,
                ):
                    with ui.row().classes('items-center justify-between w-full'):
                        cb = ui.checkbox(category, value=True)
                        checkboxes[category] = cb
                        ui.badge(str(len(items))).props('color=negative')

                        def make_handler(cat: str, cbox: ui.checkbox):
                            def _on_change():
                                if cbox.value:
                                    selected_categories.add(cat)
                                else:
                                    selected_categories.discard(cat)
                                apply_filter()
                            return _on_change

                        cb.on('update:model-value', make_handler(category, cb))

                # Select-all control
                with ui.row().classes('items-center justify-between w-full q-mt-sm'):
                    select_all_cb = ui.checkbox('Select All', value=True)
                    ui.badge(str(len(anomalies))).props('color=primary')

                    def on_select_all() -> None:
                        if select_all_cb.value:
                            selected_categories.update(categories.keys())
                            for c in checkboxes.values():
                                c.value = True
                        else:
                            selected_categories.clear()
                            for c in checkboxes.values():
                                c.value = False
                        apply_filter()

                    select_all_cb.on('update:model-value', on_select_all)

            # -----------------------------------------------------------------
            # Anomaly details table
            # -----------------------------------------------------------------
            anomaly_columns = [
                {'name': 'file',        'label': 'File',      'field': 'file',        'align': 'left'},
                {'name': 'device',      'label': 'Device',    'field': 'device',      'align': 'left'},
                {'name': 'line',        'label': 'Line',      'field': 'line',        'align': 'left'},
                {'name': 'line_number', 'label': 'Line #',    'field': 'line_number', 'align': 'left'},
                {'name': 'category',    'label': 'Category',  'field': 'category',    'align': 'left'},
                {'name': 'timestamp',   'label': 'Timestamp', 'field': 'timestamp',   'align': 'left'},
                {'name': 'log_line',    'label': 'Log Line',  'field': 'line',        'align': 'left'},
                {'name': 'actions',     'label': 'Actions',   'field': 'file',        'align': 'left'},
            ]

            details_table = ui.table(
                columns=anomaly_columns,
                rows=anomalies,
                row_key='timestamp',
            ).classes('w-full')

            # Add view button slot; emit the whole row payload
            details_table.add_slot('body-cell-actions', r"""
                <q-td :props="props" auto-width>
                  <q-btn dense flat color="primary" icon="visibility" label="View"
                         @click="() => $parent.$emit('view-anomaly', props.row)" />
                </q-td>
            """)

            # Simple file cache to avoid rereads
            _file_cache: Dict[str, List[str]] = {}

            def _get_file_lines(path: str) -> List[str]:
                if path not in _file_cache:
                    try:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                            _file_cache[path] = fh.read().splitlines()
                    except Exception:
                        _file_cache[path] = []
                return _file_cache[path]

            # Track dialog stacking & positions
            _dialog_count = 0

            def handle_view_anomaly(e) -> None:
                """Handle view-anomaly button clicks (parallel draggable dialog)."""
                nonlocal _dialog_count

                try:
                    # Get row data from event
                    row_data = e.args if hasattr(e, 'args') else None
                    if not isinstance(row_data, dict):
                        ui.notify('Unable to open anomaly details – no row data.', type='warning')
                        return

                    file_path = row_data.get('full_path') or row_data.get('file')
                    line_no = row_data.get('line_number', 1)

                    if not file_path or not os.path.exists(file_path):
                        ui.notify('Original log file not found on disk.', type='negative')
                        return

                    try:
                        line_no = int(line_no)
                    except Exception:
                        line_no = 1

                    # Force unique dialog id
                    dialog_id = str(uuid.uuid4())
                    offset_x = (_dialog_count * 50) % 300
                    offset_y = (_dialog_count * 40) % 200
                    _dialog_count += 1

                    # Local vars for dialog
                    current_file = file_path
                    lines = _get_file_lines(file_path)
                    total = len(lines)
                    current_target_line = max(1, min(line_no, total if total > 0 else 1))

                    # Create dialog with unique id, non-blocking
                    detail_dialog = ui.dialog().props(
                        f'persistent seamless id=anomaly-dialog-{dialog_id}'
                    )

                    # ---------------------- Z-INDEX MANAGEMENT JS ----------------------
                    ui.run_javascript(f"""
                        if (typeof window.lastZIndex === 'undefined') {{
                            window.lastZIndex = 9000;
                        }}
                        function activateDialog(dialogId) {{
                            window.lastZIndex += 100;
                            const dialog = document.getElementById('anomaly-dialog-' + dialogId);
                            if (!dialog) return;
                            const card = dialog.querySelector('.q-card');
                            if (!card) return;
                            card.style.zIndex = window.lastZIndex;
                        }}
                        window.activateDialog = activateDialog;
                        activateDialog('{dialog_id}');
                    """)

                    # ---------------------- DRAGGABLE CARD JS -------------------------
                    ui.run_javascript(f"""
                        (function() {{
                            const dialog = document.getElementById('anomaly-dialog-{dialog_id}');
                            if (!dialog) return;
                            const card = dialog.querySelector('.q-card');
                            if (!card) return;

                            let isDragging = false;
                            let currentX, currentY;
                            let initialX, initialY;
                            let xOffset = {50 + offset_x};
                            let yOffset = {50 + offset_y};

                            card.style.position = 'fixed';
                            card.style.left = xOffset + 'px';
                            card.style.top = yOffset + 'px';

                            if (!window.dialogPositions) window.dialogPositions = {{}};
                            window.dialogPositions['{dialog_id}'] = {{x: xOffset, y: yOffset}};

                            function dragStart(e) {{
                                window.activateDialog('{dialog_id}');
                                if (e.target.closest('.q-btn') ||
                                    e.target.closest('input') ||
                                    e.target.closest('textarea')) return;

                                const pos = window.dialogPositions['{dialog_id}'] || {{x: xOffset, y: yOffset}};
                                xOffset = pos.x;
                                yOffset = pos.y;

                                if (e.type === 'touchstart') {{
                                    initialX = e.touches[0].clientX - xOffset;
                                    initialY = e.touches[0].clientY - yOffset;
                                }} else {{
                                    initialX = e.clientX - xOffset;
                                    initialY = e.clientY - yOffset;
                                }}

                                if (e.target === card || e.target.closest('.text-h6')) {{
                                    isDragging = true;
                                    card.style.cursor = 'grabbing';
                                }}
                            }}

                            function dragEnd() {{
                                initialX = currentX;
                                initialY = currentY;
                                isDragging = false;
                                card.style.cursor = 'move';
                            }}

                            function drag(e) {{
                                if (!isDragging) return;
                                e.preventDefault();

                                if (e.type === 'touchmove') {{
                                    currentX = e.touches[0].clientX - initialX;
                                    currentY = e.touches[0].clientY - initialY;
                                }} else {{
                                    currentX = e.clientX - initialX;
                                    currentY = e.clientY - initialY;
                                }}

                                const maxX = window.innerWidth - card.offsetWidth;
                                const maxY = window.innerHeight - card.offsetHeight;
                                xOffset = Math.max(0, Math.min(currentX, maxX));
                                yOffset = Math.max(0, Math.min(currentY, maxY));

                                card.style.left = xOffset + 'px';
                                card.style.top = yOffset + 'px';

                                if (!window.dialogPositions) window.dialogPositions = {{}};
                                window.dialogPositions['{dialog_id}'] = {{x: xOffset, y: yOffset}};
                            }}

                            card.addEventListener('mousedown', dragStart, false);
                            document.addEventListener('mouseup',   dragEnd,   false);
                            document.addEventListener('mousemove', drag,      false);
                            card.addEventListener('touchstart',    dragStart, false);
                            document.addEventListener('touchend',  dragEnd,   false);
                            document.addEventListener('touchmove', drag,      false);
                        }})();
                    """)

                    # ---------------------- DIALOG CONTENT ----------------------------
                    def _render_context(center_line: int,
                                        lines_before: int = 20,
                                        lines_after: int = 20,
                                        highlight_line: Optional[int] = None) -> None:
                        nonlocal current_target_line

                        if not lines:
                            return

                        total_lines = len(lines)
                        center_line_clamped = max(1, min(center_line, total_lines))
                        current_target_line = center_line_clamped

                        start = max(1, center_line_clamped - lines_before)
                        end = min(total_lines, center_line_clamped + lines_after)

                        from html import escape as _esc
                        parts: List[str] = []

                        # inline CSS for log viewer
                        style = """
<style>
.log-viewer {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace;
  white-space: pre;
  background: #0b0f19;
  color: #e5e7eb;
  padding: 12px;
  border-radius: 8px;
  max-height: 600px;
  overflow: auto;
  border: 1px solid #1f2937;
}
.log-line { display: block; }
.log-line-target { background:#374151; color:#fbbf24; }
</style>
"""
                        parts.append(style)
                        parts.append(
                            f"<div class='text-caption text-grey-5 q-mb-sm'>"
                            f"Showing lines {start}-{end} of {total_lines} "
                            f"(±{lines_before}/{lines_after} around target)</div>"
                        )
                        parts.append("<div class='log-viewer'>")

                        width = len(str(end))
                        for idx in range(start, end + 1):
                            text = lines[idx - 1]
                            ln = str(idx).rjust(width)
                            cls = 'log-line'
                            if highlight_line is None:
                                if idx == current_target_line:
                                    cls = 'log-line log-line-target'
                            else:
                                if idx == highlight_line:
                                    cls = 'log-line log-line-target'
                            parts.append(
                                f"<span class='{cls}'>{_esc(ln)}: {_esc(text)}</span>"
                            )

                        parts.append('</div>')

                        html_content = ''.join(parts)
                        log_html.set_content(html_content)

                    with detail_dialog:
                        with ui.card().classes(
                            'w-[1100px] max-w-[95vw] q-pa-md relative'
                        ).style(
                            f'position: fixed; top: {50 + offset_y}px; left: {50 + offset_x}px'
                        ) as dialog_card:

                            # drag handle is basically the header row
                            with ui.row().classes('items-center justify-between w-full q-mb-sm'):
                                ui.label(os.path.basename(current_file)).classes(
                                    'text-h6 text-weight-bold q-mr-sm'
                                )
                                ui.label(f'Line {current_target_line}').classes('text-caption')

                                ui.button('Close', on_click=detail_dialog.close).props(
                                    'flat dense round color=negative'
                                )

                            log_html = ui.html().classes('w-full')

                            # initial render
                            _render_context(current_target_line)

                    detail_dialog.open()

                except Exception as ex:
                    print(f'Error in handle_view_anomaly: {ex}')
                    ui.notify('Error opening anomaly details.', type='negative')

            # Bind view-anomaly event
            details_table.on('view-anomaly', handle_view_anomaly)

            # Export button
            with ui.row().classes('q-mt-md'):
                ui.button(
                    'Export to JSON',
                    on_click=lambda: export_anomalies(details_table.rows),
                    icon='download',
                ).props('outline')


# assumes these already exist elsewhere in your file:
# DEFAULT_ANOMALY_PATTERNS: Dict[str, str]
# ANOMALY_DETECTOR with .patterns, .custom_patterns, .load_pattern_file(), ._compile_patterns(), .detect_anomalies()
# STATE with .live_anomaly_table
# get_uploaded_content(), clear_live_anomalies(), export_anomalies()


def create_live_anomaly_tab():
    """Create the Live Anomaly detection tab"""

    # ---------- HEADER ----------
    with ui.column().classes("w-full q-gutter-md"):
        ui.label("Live Anomaly Detection").classes("text-h6 text-weight-bold")
        ui.label("Monitor real-time device logs for anomalies during test execution") \
            .classes("text-body2 text-grey-7")

        # ==========================================================
        # PATTERN MANAGEMENT
        # ==========================================================
        with ui.card().classes("w-full q-pa-md"):
            ui.label("Pattern Management") \
              .classes("text-subtitle1 text-weight-bold q-mb-sm")
            ui.label("Manage anomaly detection patterns – upload files or edit patterns directly") \
              .classes("text-caption text-grey-7 q-mb-md")

            pattern_status = ui.label(
                f"Using {len(ANOMALY_DETECTOR.patterns)} patterns "
                f"({len(DEFAULT_ANOMALY_PATTERNS)} default + "
                f"{len(ANOMALY_DETECTOR.custom_patterns)} custom)"
            ).classes("text-positive")

            with ui.tabs().classes("w-full") as pattern_tabs:
                upload_tab = ui.tab("Upload File", icon="upload_file")
                edit_tab = ui.tab("Edit Patterns", icon="edit")
                export_tab = ui.tab("Export", icon="download")

            with ui.tab_panels(pattern_tabs, value=upload_tab).classes("w-full"):

                # ---------- Upload tab ----------
                with ui.tab_panel(upload_tab):
                    ui.label("Upload Exception Pattern File") \
                        .classes("text-body2 text-weight-bold q-mb-sm")
                    ui.label("Upload a .py file containing exception_patterns") \
                        .classes("text-caption text-grey-7 q-mb-md")

                    def handle_pattern_upload(e):
                        try:
                            # Save uploaded file temporarily
                            content = get_uploaded_content(e)
                            temp_path = "temp_exception_patterns.py"
                            with open(temp_path, "wb") as f:
                                f.write(content)

                            # Load patterns
                            success, message = ANOMALY_DETECTOR.load_pattern_file(temp_path)

                            if success:
                                pattern_status.text = f"✔ {message}"
                                pattern_status.classes("text-positive")
                                ui.notify(message, type="positive")
                                if "pattern_table" in locals():
                                    refresh_pattern_table()
                            else:
                                pattern_status.text = f"✖ {message}"
                                pattern_status.classes("text-negative")
                                ui.notify(message, type="negative")

                            # Clean up temp file
                            try:
                                os.remove(temp_path)
                            except Exception:
                                pass

                        except Exception as ex:
                            pattern_status.text = f"✖ Error: {str(ex)}"
                            pattern_status.classes("text-negative")
                            ui.notify(f"Error: {str(ex)}", type="negative")

                    ui.upload(
                        label="Upload Exception Pattern .py file",
                        on_upload=handle_pattern_upload,
                        auto_upload=True,
                    ).props("accept=.py").classes("w-full")

                # ---------- Edit Patterns tab ----------
                with ui.tab_panel(edit_tab):
                    ui.label("Pattern Editor") \
                        .classes("text-body2 text-weight-bold q-mb-sm")
                    ui.label("Add, edit, or delete anomaly detection patterns") \
                        .classes("text-caption text-grey-7 q-mb-md")

                    # ---- Add new pattern section ----
                    with ui.expansion("Add New Pattern", icon="add").classes("w-full q-mb-md"):
                        with ui.row().classes("w-full items-end q-gutter-sm"):
                            new_pattern_input = ui.input(
                                "Regex Pattern",
                                placeholder="e.g., error|fail|exception",
                            ).classes("flex-grow")
                            new_category_input = ui.input(
                                "Category",
                                placeholder="e.g., ERROR_GENERAL",
                            ).classes("w-48")

                        def add_new_pattern():
                            pattern = new_pattern_input.value.strip()
                            category = new_category_input.value.strip()

                            if not pattern or not category:
                                ui.notify("Both pattern and category are required", type="warning")
                                return

                            # Test regex validity
                            try:
                                re.compile(pattern, re.IGNORECASE)
                            except re.error as ex:
                                ui.notify(f"Invalid regex pattern: {str(ex)}", type="negative")
                                return

                            # Add to custom + main patterns
                            ANOMALY_DETECTOR.custom_patterns[pattern] = category
                            ANOMALY_DETECTOR.patterns[pattern] = category
                            ANOMALY_DETECTOR._compile_patterns()

                            # Clear inputs
                            new_pattern_input.value = ""
                            new_category_input.value = ""

                            # Refresh displays
                            pattern_status.text = (
                                f"Using {len(ANOMALY_DETECTOR.patterns)} patterns "
                                f"({len(DEFAULT_ANOMALY_PATTERNS)} default + "
                                f"{len(ANOMALY_DETECTOR.custom_patterns)} custom)"
                            )
                            refresh_pattern_table()
                            ui.notify(f"Added pattern: {pattern} -> {category}", type="positive")

                        ui.button("Add Pattern", icon="add", on_click=add_new_pattern) \
                          .props("color=primary")

                    # ---- Pattern table (defaults + custom) ----
                    pattern_columns = [
                        {"name": "pattern", "label": "Regex Pattern", "field": "pattern", "align": "left"},
                        {"name": "category", "label": "Category", "field": "category", "align": "left"},
                        {"name": "type", "label": "Type", "field": "type", "align": "left"},
                        {"name": "actions", "label": "Actions", "field": "pattern", "align": "left"},
                    ]

                    def get_pattern_rows():
                        rows: List[Dict[str, Any]] = []
                        # default patterns
                        for pattern, category in DEFAULT_ANOMALY_PATTERNS.items():
                            rows.append({
                                "pattern": pattern,
                                "category": category,
                                "type": "Default",
                                "is_default": True,
                            })
                        # custom patterns
                        for pattern, category in ANOMALY_DETECTOR.custom_patterns.items():
                            rows.append({
                                "pattern": pattern,
                                "category": category,
                                "type": "Custom",
                                "is_default": False,
                            })
                        return rows

                    pattern_table = ui.table(
                        columns=pattern_columns,
                        rows=get_pattern_rows(),
                        row_key="pattern",
                    ).classes("w-full")

                    # Vue slot for edit/delete/copy buttons
                    pattern_table.add_slot("body-cell-actions", r"""
                        <q-td :props="props" auto-width>
                          <q-btn dense flat color="primary" icon="edit"
                                 @click.stop.prevent="$parent.$emit('edit-pattern', props.row)"
                                 title="Edit Pattern" />
                          <q-btn dense flat color="negative" icon="delete"
                                 @click.stop.prevent="$parent.$emit('delete-pattern', props.row)"
                                 title="Delete Pattern" />
                          <q-btn v-if="!props.row.is_default" dense flat color="secondary"
                                 icon="content_copy"
                                 @click.stop.prevent="$parent.$emit('copy-pattern', props.row)"
                                 title="Copy to Custom" />
                        </q-td>
                    """)

                    def refresh_pattern_table():
                        pattern_table.rows = get_pattern_rows()
                        pattern_table.update()

                    # ---- Edit dialog ----
                    edit_dialog = ui.dialog()

                    def show_edit_dialog(pattern_data: Dict[str, Any]):
                        edit_dialog.clear()
                        with edit_dialog:
                            with ui.card().classes("w-96 q-pa-md"):
                                ui.label("Edit Pattern").classes("text-h6 text-weight-bold q-mb-md")
                                edit_pattern_input = ui.input(
                                    "Regex Pattern",
                                    value=pattern_data["pattern"],
                                ).classes("w-full q-mb-sm")
                                edit_category_input = ui.input(
                                    "Category",
                                    value=pattern_data["category"],
                                ).classes("w-full q-mb-md")

                                with ui.row().classes("w-full justify-end q-gutter-sm"):
                                    ui.button("Cancel", on_click=edit_dialog.close).props("flat")

                                    def save_edit():
                                        old_pattern = pattern_data["pattern"]
                                        new_pattern = edit_pattern_input.value.strip()
                                        new_category = edit_category_input.value.strip()
                                        is_default = pattern_data.get("is_default", False)

                                        if not new_pattern or not new_category:
                                            ui.notify("Both pattern and category are required", type="warning")
                                            return

                                        # validate regex
                                        try:
                                            re.compile(new_pattern, re.IGNORECASE)
                                        except re.error as ex:
                                            ui.notify(f"Invalid regex pattern: {str(ex)}", type="negative")
                                            return

                                        if is_default:
                                            # update global defaults
                                            global DEFAULT_ANOMALY_PATTERNS
                                            DEFAULT_ANOMALY_PATTERNS = dict(DEFAULT_ANOMALY_PATTERNS)
                                            if old_pattern in DEFAULT_ANOMALY_PATTERNS:
                                                del DEFAULT_ANOMALY_PATTERNS[old_pattern]
                                            DEFAULT_ANOMALY_PATTERNS[new_pattern] = new_category
                                            ANOMALY_DETECTOR.patterns = {
                                                **DEFAULT_ANOMALY_PATTERNS,
                                                **ANOMALY_DETECTOR.custom_patterns,
                                            }
                                            ui.notify(
                                                f"Edited default pattern: {new_pattern} -> {new_category}",
                                                type="positive",
                                            )
                                        else:
                                            # edit in custom patterns
                                            if old_pattern in ANOMALY_DETECTOR.custom_patterns:
                                                del ANOMALY_DETECTOR.custom_patterns[old_pattern]
                                            if old_pattern in ANOMALY_DETECTOR.patterns:
                                                del ANOMALY_DETECTOR.patterns[old_pattern]

                                            ANOMALY_DETECTOR.custom_patterns[new_pattern] = new_category
                                            ANOMALY_DETECTOR.patterns[new_pattern] = new_category
                                            ui.notify(
                                                f"Edited custom pattern: {new_pattern} -> {new_category}",
                                                type="positive",
                                            )

                                        ANOMALY_DETECTOR._compile_patterns()
                                        pattern_status.text = (
                                            f"Using {len(ANOMALY_DETECTOR.patterns)} patterns "
                                            f"({len(DEFAULT_ANOMALY_PATTERNS)} default + "
                                            f"{len(ANOMALY_DETECTOR.custom_patterns)} custom)"
                                        )
                                        refresh_pattern_table()
                                        edit_dialog.close()

                                    ui.button("Save", on_click=save_edit).props("color=primary")

                        edit_dialog.open()

                    # ---- table event handlers ----
                    def handle_edit_pattern(e):
                        row_data = e.args if hasattr(e, "args") else None
                        if row_data:
                            show_edit_dialog(row_data)

                    def handle_delete_pattern(e):
                        row_data = e.args if hasattr(e, "args") else None
                        if not row_data:
                            return

                        pattern = row_data["pattern"]
                        is_default = row_data.get("is_default", False)

                        if is_default:
                            global DEFAULT_ANOMALY_PATTERNS
                            DEFAULT_ANOMALY_PATTERNS = dict(DEFAULT_ANOMALY_PATTERNS)
                            if pattern in DEFAULT_ANOMALY_PATTERNS:
                                del DEFAULT_ANOMALY_PATTERNS[pattern]
                            ANOMALY_DETECTOR.patterns = {
                                **DEFAULT_ANOMALY_PATTERNS,
                                **ANOMALY_DETECTOR.custom_patterns,
                            }
                            ui.notify(f"Deleted default pattern: {pattern}", type="positive")
                        else:
                            if pattern in ANOMALY_DETECTOR.custom_patterns:
                                del ANOMALY_DETECTOR.custom_patterns[pattern]
                            if pattern in ANOMALY_DETECTOR.patterns:
                                del ANOMALY_DETECTOR.patterns[pattern]
                            ui.notify(f"Deleted custom pattern: {pattern}", type="positive")

                        ANOMALY_DETECTOR._compile_patterns()
                        pattern_status.text = (
                            f"Using {len(ANOMALY_DETECTOR.patterns)} patterns "
                            f"({len(DEFAULT_ANOMALY_PATTERNS)} default + "
                            f"{len(ANOMALY_DETECTOR.custom_patterns)} custom)"
                        )
                        refresh_pattern_table()

                    def handle_copy_pattern(e):
                        row_data = e.args if hasattr(e, "args") else None
                        if not row_data:
                            return

                        pattern = row_data["pattern"]
                        category = row_data["category"]

                        ANOMALY_DETECTOR.custom_patterns[pattern] = category
                        ANOMALY_DETECTOR.patterns[pattern] = category
                        ANOMALY_DETECTOR._compile_patterns()

                        pattern_status.text = (
                            f"Using {len(ANOMALY_DETECTOR.patterns)} patterns "
                            f"({len(DEFAULT_ANOMALY_PATTERNS)} default + "
                            f"{len(ANOMALY_DETECTOR.custom_patterns)} custom)"
                        )
                        refresh_pattern_table()
                        ui.notify(f"Copied pattern to custom: {pattern}", type="positive")

                    pattern_table.on("edit-pattern", handle_edit_pattern)
                    pattern_table.on("delete-pattern", handle_delete_pattern)
                    pattern_table.on("copy-pattern", handle_copy_pattern)

                # ---------- Export tab ----------
                with ui.tab_panel(export_tab):
                    ui.label("Export Patterns") \
                        .classes("text-body2 text-weight-bold q-mb-sm")
                    ui.label("Export current patterns to a Python file") \
                        .classes("text-caption text-grey-7 q-mb-md")

                    def export_patterns():
                        try:
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            filename = f"exception_patterns_{timestamp}.py"

                            content = "# Anomaly Detection Patterns\n\n"
                            content += (
                                "# Generated on "
                                + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                + "\n\n"
                            )
                            content += "exception_patterns = {\n"
                            for pattern, category in sorted(ANOMALY_DETECTOR.patterns.items()):
                                escaped_pattern = pattern.replace("\\", "\\\\").replace('"', '\\"')
                                content += f'    r"{escaped_pattern}": "{category}",\n'
                            content += "}\n"

                            ui.download(content.encode("utf-8"), filename=filename)
                            ui.notify(
                                f"Exported {len(ANOMALY_DETECTOR.patterns)} patterns to {filename}",
                                type="positive",
                            )
                        except Exception as e:
                            ui.notify(f"Export failed: {str(e)}", type="negative")

                    def export_custom_only():
                        try:
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            filename = f"custom_patterns_{timestamp}.py"

                            content = "# Custom Anomaly Detection Patterns\n\n"
                            content += (
                                "# Generated on "
                                + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                + "\n\n"
                            )
                            content += "exception_patterns = {\n"
                            for pattern, category in sorted(ANOMALY_DETECTOR.custom_patterns.items()):
                                escaped_pattern = pattern.replace("\\", "\\\\").replace('"', '\\"')
                                content += f'    r"{escaped_pattern}": "{category}",\n'
                            content += "}\n"

                            ui.download(content.encode("utf-8"), filename=filename)
                            ui.notify(
                                f"Exported {len(ANOMALY_DETECTOR.custom_patterns)} custom patterns "
                                f"to {filename}",
                                type="positive",
                            )
                        except Exception as e:
                            ui.notify(f"Export failed: {str(e)}", type="negative")

                    with ui.row().classes("q-gutter-sm"):
                        ui.button("Export All Patterns", icon="download",
                                  on_click=export_patterns).props("color=primary")
                        ui.button("Export Custom Only", icon="download",
                                  on_click=export_custom_only).props("outline")

                    ui.separator().classes("q-my-md")

                    ui.label("Reset Patterns") \
                        .classes("text-body2 text-weight-bold q-mb-sm")
                    ui.label("Reset patterns to default state") \
                        .classes("text-caption text-grey-7 q-mb-md")

                    def reset_to_defaults():
                        ANOMALY_DETECTOR.custom_patterns.clear()
                        ANOMALY_DETECTOR.patterns = DEFAULT_ANOMALY_PATTERNS.copy()
                        ANOMALY_DETECTOR._compile_patterns()
                        pattern_status.text = (
                            f"Using {len(ANOMALY_DETECTOR.patterns)} patterns "
                            f"({len(DEFAULT_ANOMALY_PATTERNS)} default + "
                            f"{len(ANOMALY_DETECTOR.custom_patterns)} custom)"
                        )
                        if "pattern_table" in locals():
                            refresh_pattern_table()
                        ui.notify("Reset to default patterns", type="positive")

                    ui.button("Reset to Defaults", icon="restore",
                              on_click=reset_to_defaults).props("color=negative outline")

        # ==========================================================
        # LIVE ANOMALY DISPLAY
        # ==========================================================
        with ui.card().classes("w-full q-pa-md"):
            ui.label("Detected Anomalies") \
                .classes("text-subtitle1 text-weight-bold q-mb-sm")
            ui.label("Anomalies will appear here when detected in live logs") \
                .classes("text-caption text-grey-7 q-mb-md")

            # ---- Manual log test / snippet ----
            with ui.expansion("Test with Log Input", icon="text_snippet").classes("w-full q-mb-md"):
                ui.label("Paste log text to test anomaly detection") \
                    .classes("text-caption text-grey-7 q-mb-sm")
                log_input = ui.textarea("Log Text", placeholder="Paste log text here...") \
                    .classes("w-full").props("rows=4")

                def analyze_log_text():
                    log_text = log_input.value
                    if not log_text:
                        ui.notify("Please enter log text to analyze", type="warning")
                        return

                    anomalies = ANOMALY_DETECTOR.detect_anomalies(log_text)
                    if not anomalies:
                        ui.notify("No anomalies detected in the provided log text", type="info")
                        return

                    formatted: List[Dict[str, Any]] = []
                    for anom in anomalies:
                        formatted.append({
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "testplan": "Manual Test",
                            "testcase": "Manual Input",
                            "device": "Log Analysis",
                            "line_number": anom.get("line_number", 0),
                            "category": anom.get("category", ""),
                            "line": anom.get("line", ""),
                        })

                    anomaly_table.rows = formatted
                    anomaly_table.update()
                    ui.notify(f"Detected {len(anomalies)} anomalies", type="positive")

                ui.button("Analyze Log", icon="search",
                          on_click=analyze_log_text).props("color=primary")

            # ---- live anomaly table ----
            anomaly_columns = [
                {"name": "timestamp", "label": "Timestamp", "field": "timestamp", "align": "left"},
                {"name": "testplan", "label": "Testplan", "field": "testplan", "align": "left"},
                {"name": "testcase", "label": "Testcase", "field": "testcase", "align": "left"},
                {"name": "device", "label": "Device", "field": "device", "align": "left"},
                {"name": "line_number", "label": "Line", "field": "line_number", "align": "left"},
                {"name": "category", "label": "Category", "field": "category", "align": "left"},
                {"name": "line", "label": "Log Line", "field": "line", "align": "left"},
                {"name": "actions", "label": "Actions", "field": "timestamp", "align": "left"},
            ]

            anomaly_table = ui.table(
                columns=anomaly_columns,
                rows=[],
                row_key="timestamp",
            ).classes("w-full")

            # View button slot
            anomaly_table.add_slot("body-cell-actions", r"""
                <q-td :props="props" auto-width>
                  <q-btn dense flat color="primary" icon="visibility" label="View"
                         @click.stop.prevent="$parent.$emit('view-anomaly', props.row)" />
                </q-td>
            """)

            # ---------- view dialog handler ----------
            def handle_live_view_anomaly(e):
                """Handle view anomaly button clicks for live anomalies (parallel dialogs)."""
                try:
                    import uuid
                    row_data = e.args if hasattr(e, "args") else None
                    if not isinstance(row_data, dict):
                        ui.notify("Unable to open anomaly details - no row data.", type="warning")
                        return

                    line = row_data.get("line", "")
                    category = row_data.get("category", "")
                    device = row_data.get("device", "")
                    timestamp = row_data.get("timestamp", "")

                    dialog_id = str(uuid.uuid4())

                    detail_dialog = ui.dialog() \
                        .props(f"persistent seamless id=anomaly-dialog-{dialog_id}")

                    with detail_dialog:
                        card = ui.card().classes("w-[700px] max-w-[95vw] q-pa-md") \
                            .style("z-index:1000; cursor: move; position: fixed; top: 50px; left: 50px;")

                        with card:
                            ui.label(f"Anomaly Detail - {category}") \
                              .classes("text-h6 text-weight-bold q-mb-md")

                            with ui.column().classes("w-full q-gutter-sm"):
                                with ui.row().classes("items-center q-gutter-sm"):
                                    ui.icon("event")
                                    ui.label(timestamp).classes("text-body2")

                                with ui.row().classes("items-center q-gutter-sm"):
                                    ui.icon("devices")
                                    ui.label(device).classes("text-body2")

                                ui.separator()

                                ui.label("Log Line") \
                                  .classes("text-body2 text-weight-bold")
                                ui.card().classes("w-full q-pa-sm bg-grey-2").props("flat"):
                                # simple mono log text
                                ui.label(line).classes("text-body2 text-mono")

                                ui.button("Close", on_click=detail_dialog.close) \
                                  .props("color=primary q-mt-md")

                    # draggable JS (same idea as screenshots)
                    ui.run_javascript(f"""
                        (function() {{
                          const dialog = document.getElementById("anomaly-dialog-{dialog_id}");
                          if (!dialog) return;
                          const card = dialog.querySelector(".q-card");
                          if (!card) return;

                          let isDragging = false;
                          let startX = 0, startY = 0;

                          function dragStart(e) {{
                            if (e.target.closest(".q-btn") ||
                                e.target.closest("input") ||
                                e.target.closest("textarea")) return;

                            isDragging = true;
                            card.style.cursor = "grabbing";
                            const rect = card.getBoundingClientRect();
                            if (e.type === "touchstart") {{
                              startX = e.touches[0].clientX - rect.left;
                              startY = e.touches[0].clientY - rect.top;
                            }} else {{
                              startX = e.clientX - rect.left;
                              startY = e.clientY - rect.top;
                            }}
                          }}

                          function dragEnd() {{
                            isDragging = false;
                            card.style.cursor = "move";
                          }}

                          function drag(e) {{
                            if (!isDragging) return;
                            e.preventDefault();
                            let clientX, clientY;
                            if (e.type === "touchmove") {{
                              clientX = e.touches[0].clientX;
                              clientY = e.touches[0].clientY;
                            }} else {{
                              clientX = e.clientX;
                              clientY = e.clientY;
                            }}
                            let x = clientX - startX;
                            let y = clientY - startY;

                            const maxX = window.innerWidth - card.offsetWidth;
                            const maxY = window.innerHeight - card.offsetHeight;
                            x = Math.max(0, Math.min(x, maxX));
                            y = Math.max(0, Math.min(y, maxY));

                            card.style.left = x + "px";
                            card.style.top = y + "px";
                          }}

                          card.addEventListener("mousedown", dragStart, false);
                          document.addEventListener("mouseup", dragEnd, false);
                          document.addEventListener("mousemove", drag, false);
                          card.addEventListener("touchstart", dragStart, false);
                          document.addEventListener("touchend", dragEnd, false);
                          document.addEventListener("touchmove", drag, {{passive:false}});
                        }})();
                    """)

                    detail_dialog.open()

                except Exception as ex:
                    print(f"Error in handle_live_view_anomaly: {ex}")
                    ui.notify("Error opening anomaly details.", type="negative")

            # bind event
            anomaly_table.on("view-anomaly", handle_live_view_anomaly)

        # Save reference for external updates
        STATE.live_anomaly_table = anomaly_table

        # Footer buttons
        with ui.row().classes("q-mt-md"):
            ui.button(
                "Clear Anomalies",
                on_click=lambda: clear_live_anomalies(anomaly_table),
                icon="clear",
            ).props("outline")
            ui.button(
                "Export to JSON",
                on_click=lambda: export_anomalies(anomaly_table.rows),
                icon="download",
            ).props("outline")


# ---------------------------------------------------------------------
# Main page + NiceGUI app bootstrap
# ---------------------------------------------------------------------

def create_offline_anomaly_tab() -> None:
    """Create the Offline Anomaly detection tab"""

    with ui.column().classes('w-full q-gutter-md'):
        ui.label('Offline Anomaly Detection').classes('text-h6 text-weight-bold')
        ui.label('Analyze existing log files for anomalies').classes(
            'text-body2 text-grey-7'
        )

        # ---------------------------
        # Pattern management section
        # ---------------------------
        with ui.card().classes('w-full q-pa-md') as pattern_card:
            ui.label('Pattern Management').classes(
                'text-subtitle1 text-weight-bold q-mb-sm'
            )
            ui.label(
                'Manage anomaly detection patterns - upload files or edit patterns directly'
            ).classes('text-caption text-grey-7 q-mb-md')

            pattern_status = ui.label(
                f"Using {len(ANOMALY_DETECTOR.patterns)} patterns "
                f"({len(DEFAULT_ANOMALY_PATTERNS)} default + "
                f"{len(ANOMALY_DETECTOR.custom_patterns)} custom)"
            ).classes('text-positive')

            with ui.tabs().classes('w-full') as offline_pattern_tabs:
                upload_tab = ui.tab('Upload File', icon='upload_file')
                edit_tab = ui.tab('Edit Patterns', icon='edit')
                export_tab = ui.tab('Export', icon='download')

            # -------------------------------------------------
            # Upload / Edit / Export tab panels
            # -------------------------------------------------
            with ui.tab_panels(offline_pattern_tabs, value=upload_tab).classes('w-full'):
                # ----------------- Upload tab ------------------
                with ui.tab_panel(upload_tab):
                    ui.label('Upload Exception Pattern File').classes(
                        'text-body2 text-weight-bold q-mb-sm'
                    )
                    ui.label(
                        'Upload a .py file containing exception patterns'
                    ).classes('text-caption text-grey-7 q-mb-md')

                    def handle_offline_pattern_upload(e) -> None:
                        try:
                            content = get_uploaded_content(e)
                            temp_path = 'temp_offline_exception_patterns.py'
                            with open(temp_path, 'wb') as f:
                                f.write(content)

                            success, message = ANOMALY_DETECTOR.load_pattern_file(
                                temp_path
                            )
                            if success:
                                pattern_status.text = f'✅ {message}'
                                pattern_status.classes('text-positive')
                                ui.notify(message, type='positive')
                                if 'offline_pattern_table' in locals():
                                    refresh_offline_pattern_table()
                            else:
                                pattern_status.text = f'❌ {message}'
                                pattern_status.classes('text-negative')
                                ui.notify(message, type='negative')

                            try:
                                os.remove(temp_path)
                            except Exception:
                                pass
                        except Exception as ex:
                            msg = f'⚠️ Error: {str(ex)}'
                            pattern_status.text = msg
                            pattern_status.classes('text-negative')
                            ui.notify(msg, type='negative')

                    ui.upload(
                        label='Upload Exception Pattern .py File',
                        on_upload=handle_offline_pattern_upload,
                        auto_upload=True,
                    ).props('accept=.py').classes('w-full')

                # ----------------- Edit tab --------------------
                with ui.tab_panel(edit_tab):
                    ui.label('Pattern Editor').classes(
                        'text-body2 text-weight-bold q-mb-sm'
                    )
                    ui.label(
                        'Add, edit, or delete anomaly detection patterns'
                    ).classes('text-caption text-grey-7 q-mb-md')

                    # --- Add new pattern section
                    with ui.expansion('Add New Pattern', icon='add').classes(
                        'w-full q-mb-md'
                    ):
                        with ui.row().classes('w-full items-end q-gutter-sm'):
                            offline_new_pattern_input = ui.input(
                                'Regex Pattern',
                                placeholder=r'e.g., ERROR|FAIL|exception',
                            ).classes('flex-grow')
                            offline_new_category_input = ui.input(
                                'Category',
                                placeholder='e.g., ERROR_GENERAL',
                            ).classes('w-48')

                        def offline_add_new_pattern() -> None:
                            pattern = offline_new_pattern_input.value.strip()
                            category = offline_new_category_input.value.strip()
                            if not pattern or not category:
                                ui.notify(
                                    'Both pattern and category are required',
                                    type='warning',
                                )
                                return
                            try:
                                re.compile(pattern, re.IGNORECASE)
                            except re.error as ex:
                                ui.notify(
                                    f'Invalid regex pattern: {str(ex)}',
                                    type='negative',
                                )
                                return

                            ANOMALY_DETECTOR.custom_patterns[pattern] = category
                            ANOMALY_DETECTOR.patterns[pattern] = category
                            ANOMALY_DETECTOR._compile_patterns()  # re-compile

                            offline_new_pattern_input.value = ''
                            offline_new_category_input.value = ''

                            pattern_status.text = (
                                f"Using {len(ANOMALY_DETECTOR.patterns)} patterns "
                                f"({len(DEFAULT_ANOMALY_PATTERNS)} default + "
                                f"{len(ANOMALY_DETECTOR.custom_patterns)} custom)"
                            )
                            refresh_offline_pattern_table()
                            ui.notify(
                                f'Added pattern: {pattern} -> {category}',
                                type='positive',
                            )

                        ui.button(
                            'Add Pattern',
                            icon='add',
                            on_click=offline_add_new_pattern,
                        ).props('color=primary')

                    # --- Pattern table definition
                    offline_pattern_columns = [
                        {
                            'name': 'pattern',
                            'label': 'Regex Pattern',
                            'field': 'pattern',
                            'align': 'left',
                        },
                        {
                            'name': 'category',
                            'label': 'Category',
                            'field': 'category',
                            'align': 'left',
                        },
                        {
                            'name': 'type',
                            'label': 'Type',
                            'field': 'type',
                            'align': 'left',
                        },
                        {
                            'name': 'actions',
                            'label': 'Actions',
                            'field': 'pattern',
                            'align': 'left',
                        },
                    ]

                    def get_offline_pattern_rows() -> List[Dict[str, Any]]:
                        rows: List[Dict[str, Any]] = []
                        # defaults
                        for pattern, category in DEFAULT_ANOMALY_PATTERNS.items():
                            rows.append(
                                {
                                    'pattern': pattern,
                                    'category': category,
                                    'type': 'Default',
                                    'is_default': True,
                                }
                            )
                        # customs
                        for pattern, category in ANOMALY_DETECTOR.custom_patterns.items():
                            rows.append(
                                {
                                    'pattern': pattern,
                                    'category': category,
                                    'type': 'Custom',
                                    'is_default': False,
                                }
                            )
                        return rows

                    offline_pattern_table = ui.table(
                        columns=offline_pattern_columns,
                        rows=get_offline_pattern_rows(),
                        row_key='pattern',
                    ).classes('w-full')

                    # slot for edit / delete / copy buttons
                    offline_pattern_table.add_slot(
                        'body-cell-actions',
                        r"""
<q-td :props="props" auto-width>
  <q-btn dense flat color="primary" icon="edit"
         @click.stop.prevent="$parent.$emit('edit-pattern', props.row)"
         title="Edit Pattern" />
  <q-btn dense flat color="negative" icon="delete"
         @click.stop.prevent="$parent.$emit('delete-pattern', props.row)"
         title="Delete Pattern" />
  <q-btn v-if="!props.row.is_default" dense flat color="secondary" icon="content_copy"
         @click.stop.prevent="$parent.$emit('copy-pattern', props.row)"
         title="Copy to Custom" />
</q-td>
""",
                    )

                    # --- helpers to refresh table
                    def refresh_offline_pattern_table() -> None:
                        offline_pattern_table.rows = get_offline_pattern_rows()
                        offline_pattern_table.update()

                    # --- edit dialog and handlers
                    offline_edit_dialog = ui.dialog()

                    def show_offline_edit_dialog(pattern_data: Dict[str, Any]) -> None:
                        offline_edit_dialog.clear()

                        with offline_edit_dialog:
                            with ui.card().classes('w-96 q-pa-md'):
                                ui.label('Edit Pattern').classes(
                                    'text-h6 text-weight-bold q-mb-md'
                                )
                                edit_pattern_input = ui.input(
                                    'Regex Pattern',
                                    value=pattern_data['pattern'],
                                ).classes('w-full q-mb-sm')
                                edit_category_input = ui.input(
                                    'Category',
                                    value=pattern_data['category'],
                                ).classes('w-full q-mb-md')

                                def save_edit() -> None:
                                    old_pattern = pattern_data['pattern']
                                    new_pattern = edit_pattern_input.value.strip()
                                    new_category = edit_category_input.value.strip()
                                    is_default = pattern_data.get('is_default', False)

                                    if not new_pattern or not new_category:
                                        ui.notify(
                                            'Both pattern and category are required',
                                            type='warning',
                                        )
                                        return
                                    try:
                                        re.compile(new_pattern, re.IGNORECASE)
                                    except re.error as ex:
                                        ui.notify(
                                            f'Invalid regex pattern: {str(ex)}',
                                            type='negative',
                                        )
                                        return

                                    if is_default:
                                        # update global default patterns
                                        global DEFAULT_ANOMALY_PATTERNS
                                        DEFAULT_ANOMALY_PATTERNS = dict(
                                            DEFAULT_ANOMALY_PATTERNS
                                        )
                                        if old_pattern in DEFAULT_ANOMALY_PATTERNS:
                                            del DEFAULT_ANOMALY_PATTERNS[old_pattern]
                                        DEFAULT_ANOMALY_PATTERNS[new_pattern] = (
                                            new_category
                                        )
                                    else:
                                        # custom pattern update
                                        if old_pattern in ANOMALY_DETECTOR.custom_patterns:
                                            del ANOMALY_DETECTOR.custom_patterns[
                                                old_pattern
                                            ]
                                        ANOMALY_DETECTOR.custom_patterns[
                                            new_pattern
                                        ] = new_category

                                    ANOMALY_DETECTOR.patterns = {
                                        **DEFAULT_ANOMALY_PATTERNS,
                                        **ANOMALY_DETECTOR.custom_patterns,
                                    }
                                    ANOMALY_DETECTOR._compile_patterns()
                                    pattern_status.text = (
                                        f"Using {len(ANOMALY_DETECTOR.patterns)} patterns "
                                        f"({len(DEFAULT_ANOMALY_PATTERNS)} default + "
                                        f"{len(ANOMALY_DETECTOR.custom_patterns)} custom)"
                                    )
                                    refresh_offline_pattern_table()
                                    ui.notify(
                                        f'Edited pattern: {new_pattern} -> {new_category}',
                                        type='positive',
                                    )
                                    offline_edit_dialog.close()

                                with ui.row().classes('justify-end q-gutter-sm'):
                                    ui.button(
                                        'Cancel',
                                        on_click=offline_edit_dialog.close,
                                    ).props('flat')
                                    ui.button(
                                        'Save',
                                        on_click=save_edit,
                                    ).props('color=primary')

                        offline_edit_dialog.open()

                    def handle_offline_edit_pattern(e) -> None:
                        row_data = e.args if hasattr(e, 'args') else None
                        if row_data:
                            show_offline_edit_dialog(row_data)

                    def handle_offline_delete_pattern(e) -> None:
                        row_data = e.args if hasattr(e, 'args') else None
                        if not row_data:
                            return
                        pattern = row_data['pattern']
                        is_default = row_data.get('is_default', False)
                        if is_default:
                            global DEFAULT_ANOMALY_PATTERNS
                            DEFAULT_ANOMALY_PATTERNS = dict(DEFAULT_ANOMALY_PATTERNS)
                            if pattern in DEFAULT_ANOMALY_PATTERNS:
                                del DEFAULT_ANOMALY_PATTERNS[pattern]
                        else:
                            if pattern in ANOMALY_DETECTOR.custom_patterns:
                                del ANOMALY_DETECTOR.custom_patterns[pattern]
                        if pattern in ANOMALY_DETECTOR.patterns:
                            del ANOMALY_DETECTOR.patterns[pattern]

                        ANOMALY_DETECTOR._compile_patterns()
                        pattern_status.text = (
                            f"Using {len(ANOMALY_DETECTOR.patterns)} patterns "
                            f"({len(DEFAULT_ANOMALY_PATTERNS)} default + "
                            f"{len(ANOMALY_DETECTOR.custom_patterns)} custom)"
                        )
                        refresh_offline_pattern_table()
                        ui.notify(f'Deleted pattern: {pattern}', type='positive')

                    def handle_offline_copy_pattern(e) -> None:
                        row_data = e.args if hasattr(e, 'args') else None
                        if not row_data:
                            return
                        pattern = row_data['pattern']
                        category = row_data['category']
                        ANOMALY_DETECTOR.custom_patterns[pattern] = category
                        ANOMALY_DETECTOR.patterns[pattern] = category
                        ANOMALY_DETECTOR._compile_patterns()
                        pattern_status.text = (
                            f"Using {len(ANOMALY_DETECTOR.patterns)} patterns "
                            f"({len(DEFAULT_ANOMALY_PATTERNS)} default + "
                            f"{len(ANOMALY_DETECTOR.custom_patterns)} custom)"
                        )
                        refresh_offline_pattern_table()
                        ui.notify(
                            f'Copied pattern to custom: {pattern}', type='positive'
                        )

                    offline_pattern_table.on('edit-pattern', handle_offline_edit_pattern)
                    offline_pattern_table.on(
                        'delete-pattern', handle_offline_delete_pattern
                    )
                    offline_pattern_table.on(
                        'copy-pattern', handle_offline_copy_pattern
                    )

                # ----------------- Export tab ------------------
                with ui.tab_panel(export_tab):

                    def export_patterns() -> None:
                        try:
                            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                            filename = f'exception_patterns_{timestamp}.py'

                            content = (
                                '# Generated on '
                                + datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                + '\n\n'
                                'exception_patterns = {\n'
                            )
                            for pattern, category in sorted(
                                ANOMALY_DETECTOR.patterns.items()
                            ):
                                escaped_pattern = (
                                    pattern.replace('\\', '\\\\')
                                    .replace('"', '\\"')
                                    .replace("'", "\\'")
                                )
                                content += (
                                    f"    r'{escaped_pattern}': '{category}',\n"
                                )
                            content += '}\n'

                            ui.download(
                                content.encode('utf-8'), filename=filename
                            )
                            ui.notify(
                                f'Exported {len(ANOMALY_DETECTOR.patterns)} '
                                f'patterns to {filename}',
                                type='positive',
                            )
                        except Exception as e:
                            ui.notify(
                                f'Export failed: {str(e)}', type='negative'
                            )

                    def export_custom_only() -> None:
                        try:
                            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                            filename = f'custom_patterns_{timestamp}.py'

                            content = (
                                '# Generated on '
                                + datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                + '\n\n'
                                'exception_patterns = {\n'
                            )
                            for pattern, category in sorted(
                                ANOMALY_DETECTOR.custom_patterns.items()
                            ):
                                escaped_pattern = (
                                    pattern.replace('\\', '\\\\')
                                    .replace('"', '\\"')
                                    .replace("'", "\\'")
                                )
                                content += (
                                    f"    r'{escaped_pattern}': '{category}',\n"
                                )
                            content += '}\n'

                            ui.download(
                                content.encode('utf-8'), filename=filename
                            )
                            ui.notify(
                                f'Exported {len(ANOMALY_DETECTOR.custom_patterns)} '
                                f'custom patterns to {filename}',
                                type='positive',
                            )
                        except Exception as e:
                            ui.notify(
                                f'Export failed: {str(e)}', type='negative'
                            )

                    with ui.row().classes('q-gutter-sm'):
                        ui.button(
                            'Export All Patterns',
                            icon='download',
                            on_click=export_patterns,
                        ).props('color=primary')
                        ui.button(
                            'Export Custom Only',
                            icon='download',
                            on_click=export_custom_only,
                        ).props('outline')

                    ui.separator().classes('q-my-md')

                    ui.label('Reset Patterns').classes(
                        'text-body2 text-weight-bold q-mb-sm'
                    )
                    ui.label('Reset patterns to default state').classes(
                        'text-caption text-grey-7 q-mb-md'
                    )

                    def reset_to_defaults() -> None:
                        ANOMALY_DETECTOR.custom_patterns.clear()
                        ANOMALY_DETECTOR.patterns = DEFAULT_ANOMALY_PATTERNS.copy()
                        ANOMALY_DETECTOR._compile_patterns()
                        pattern_status.text = (
                            f"Using {len(ANOMALY_DETECTOR.patterns)} patterns "
                            f"({len(DEFAULT_ANOMALY_PATTERNS)} default + "
                            f"{len(ANOMALY_DETECTOR.custom_patterns)} custom)"
                        )
                        refresh_offline_pattern_table()
                        ui.notify(
                            'Reset to default patterns', type='positive'
                        )

                    ui.button(
                        'Reset to Defaults',
                        icon='restore',
                        on_click=reset_to_defaults,
                    ).props('color=negative outline')

        # -------------------------------------------------
        # Folder selection and offline analysis
        # -------------------------------------------------
        with ui.card().classes('w-full q-pa-md'):
            ui.label('Log Folder Selection').classes(
                'text-subtitle1 text-weight-bold q-mb-sm'
            )
            ui.label(
                'Enter the path to a folder containing device log files, '
                'e.g., C:/logs or /var/log/devices'
            ).classes('text-caption text-grey-7 q-mb-md')

            folder_input = ui.input(
                'Folder Path', placeholder='C:/logs or /var/log/devices'
            ).classes('w-full')

            progress_container = ui.column().classes('w-full')

            # track analysis state
            analysis_state = {'running': False, 'should_abort': False}

            def analyze_folder() -> None:
                folder_path = folder_input.value
                if not folder_path or not os.path.exists(folder_path):
                    ui.notify(
                        'Please enter a valid folder path', type='warning'
                    )
                    return

                progress_container.clear()
                with progress_container:
                    progress = ui.linear_progress(0.0).props(
                        'color=primary'
                    ).classes('w-full')
                    progress_label = ui.label(
                        'Scanning for log files...'
                    ).classes('text-caption')

                # find all log files recursively
                log_files: List[str] = []
                for root, dirs, files in os.walk(folder_path):
                    for f in files:
                        if f.lower().endswith(('.log', '.txt', '.out')):
                            log_files.append(os.path.join(root, f))

                if not log_files:
                    progress_container.clear()
                    ui.notify(
                        'No log files found in the specified folder',
                        type='warning',
                    )
                    return

                progress_label.text = (
                    f'Found {len(log_files)} log files. '
                    'Analyzing in parallel...'
                )

                # set analysis state
                analysis_state['running'] = True
                analysis_state['should_abort'] = False

                # kick off async analysis
                import asyncio as _asyncio

                _asyncio.create_task(
                    analyze_async(
                        log_files,
                        analysis_state,
                        progress,
                        progress_label,
                        progress_container,
                    )
                )

            def abort_analysis() -> None:
                if analysis_state['running']:
                    analysis_state['should_abort'] = True
                    ui.notify(
                        'Aborting analysis...', type='info'
                    )
                else:
                    ui.notify(
                        'No analysis is currently running', type='warning'
                    )

            with ui.row().classes('q-gutter-sm q-mt-md'):
                ui.button(
                    'Analyze Folder',
                    on_click=analyze_folder,
                    icon='search',
                ).props('color=primary')
                ui.button(
                    'Abort Analysis',
                    on_click=abort_analysis,
                    icon='stop',
                ).props('color=negative outline')

        # results container (shared)
        results_container = ui.column().classes('w-full')
    
    # end of create_offline_anomaly_tab
    

async def analyze_async(
    log_files: List[str],
    analysis_state: Dict[str, Any],
    progress: ui.linear_progress,
    progress_label: ui.label,
    progress_container: ui.column,
) -> None:
    """Async worker for offline log analysis"""

    # helper for single file
    def _analyze_file(log_file: str):
        if analysis_state['should_abort']:
            return []

        import time as _time
        start_time = _time.time()

        # network path check (for perf message)
        is_network_path = log_file.startswith('\\\\') or log_file.startswith('//')

        size_start = _time.time()
        file_size = os.path.getsize(log_file)
        size_time = _time.time() - size_start

        file_info = (
            f"Analyzing {log_file} (file_size = {file_size / 1024 / 1024:.1f} MB)"
        )
        print(file_info)

        read_start = _time.time()
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            log_content = f.read()
        read_time = _time.time() - read_start

        if analysis_state['should_abort']:
            print(f"Aborted while reading {os.path.basename(log_file)}")
            return []

        analyze_start = _time.time()
        anomalies = ANOMALY_DETECTOR.detect_anomalies(log_content)
        analyze_time = _time.time() - analyze_start

        for anomaly in anomalies:
            anomaly['file'] = os.path.basename(log_file)
            anomaly['full_path'] = log_file
            anomaly['device'] = extract_device_name(log_file)

        total_time = _time.time() - start_time
        perf_info = None
        if total_time > 5:
            net = '[NETWORK]' if is_network_path else '[LOCAL]'
            perf_info = (
                f"{net} {os.path.basename(log_file)} "
                f"(file_size {file_size / 1024 / 1024:.1f} MB) "
                f"total={total_time:.2f}s, read={read_time:.2f}s, "
                f"analyze={analyze_time:.2f}s"
            )
            print(perf_info)

        return anomalies, file_info, perf_info

    # ------------- concurrent execution setup -------------
    cpu_count = os.cpu_count() or 2
    max_workers = min(cpu_count * 3, len(log_files), 16)
    completed = 0
    all_anomalies: List[Dict[str, Any]] = []
    batch_size = 5  # reduced for more frequent UI updates

    client_disconnected = False
    last_successful_update = 0

    loop = asyncio.get_running_loop()

    try:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers
        ) as ex:
            pending_tasks: List[asyncio.Future] = []
            file_index = 0

            # initial batch submission
            initial_batch = min(max_workers * 2, len(log_files))
            for _ in range(initial_batch):
                if not analysis_state['should_abort'] and file_index < len(log_files):
                    task = loop.run_in_executor(ex, _analyze_file, log_files[file_index])
                    pending_tasks.append(task)
                    file_index += 1

            while pending_tasks:
                done, pending_tasks = await asyncio.wait(
                    pending_tasks,
                    return_when=asyncio.FIRST_COMPLETED,
                    timeout=60.0,
                )

                # process completed tasks
                for task in done:
                    file_msg = None
                    perf_msg = None
                    try:
                        result = await task
                        if isinstance(result, tuple) and len(result) == 3:
                            anomalies_list, file_msg, perf_msg = result
                            all_anomalies.extend(anomalies_list)
                        else:
                            all_anomalies.extend(result or [])
                    except asyncio.TimeoutError:
                        print(f'Timeout analyzing file at position {completed}')
                    except Exception as ex:
                        print(f'Error in task: {ex}')

                    completed += 1

                    # submit next file
                    if not analysis_state['should_abort'] and file_index < len(
                        log_files
                    ):
                        t = loop.run_in_executor(
                            ex, _analyze_file, log_files[file_index]
                        )
                        pending_tasks.append(t)
                        file_index += 1
                    elif analysis_state['should_abort'] and file_index < len(
                        log_files
                    ):
                        print(
                            f'Abort: stopping at {completed}/{len(log_files)} files, '
                            f'{len(pending_tasks)} tasks still running'
                        )

                    # -------- progress / status update per file --------
                    try:
                        if hasattr(progress, 'client') and hasattr(
                            progress.client, 'has_socket_connection'
                        ):
                            if progress.client.has_socket_connection():
                                new_value = completed / len(log_files)
                                progress.value = new_value
                                progress.update()

                                current_msg = (
                                    f'Analyzed {completed}/{len(log_files)} files '
                                    f'({len(all_anomalies)} anomalies)'
                                )
                                if perf_msg:
                                    current_msg = perf_msg
                                progress_label.text = current_msg
                                last_successful_update = completed
                                await asyncio.sleep(0)
                            else:
                                if not client_disconnected:
                                    print(
                                        f'Client disconnected at '
                                        f'{completed}/{len(log_files)} files '
                                        f'- continuing analysis in background'
                                    )
                                    client_disconnected = True
                        else:
                            if not client_disconnected:
                                print(
                                    'Client object not available, assume '
                                    f'disconnected at {completed}/{len(log_files)} '
                                    'files - continuing analysis in background'
                                )
                                client_disconnected = True
                    except (RuntimeError, AttributeError):
                        if not client_disconnected:
                            print(
                                f'Client disconnected at {completed}/{len(log_files)} '
                                'files - continuing analysis in background'
                            )
                            client_disconnected = True
                    except Exception as ex:
                        print(f'Error in analysis loop: {ex}')

    finally:
        # mark analysis as complete
        analysis_state['running'] = False
        print(
            f'Offline analysis completed in background: '
            f'{len(all_anomalies)} anomalies found in {completed} files'
        )

        # always show results, even if client disconnected / aborted
        try:
            if progress.client.has_socket_connection():
                progress.value = 1.0
                progress.update()
                await asyncio.sleep(0)

            progress_container.clear()
            results_container = progress_container  # reuse container
            display_offline_results(all_anomalies, results_container)

            # save anomalies JSON (helper assumed existing)
            save_path = save_anomalies_to_json(all_anomalies)
            try:
                with open(save_path, 'rb') as fh:
                    ui.download(fh.read(), filename=os.path.basename(save_path))
            except Exception:
                pass

            status_msg = (
                f'Analysis complete. Found {len(all_anomalies)} anomalies in '
                f'{completed}/{len(log_files)} files. Saved: {save_path}'
            )
            if analysis_state.get('should_abort'):
                status_msg = (
                    f'Analysis stopped. Found {len(all_anomalies)} anomalies in '
                    f'{completed}/{len(log_files)} files. Saved: {save_path}'
                )
            ui.notify(status_msg, type='positive' if not analysis_state.get(
                'should_abort'
            ) else 'warning')
        except (RuntimeError, AttributeError):
            # client is gone; just save results
            print(
                f'Client disconnected. Analysis completed: '
                f'{len(all_anomalies)} anomalies found in {completed} files'
            )
            save_anomalies_to_json(all_anomalies)


# ---------------------------------------------------------------------
# Offline results table + parallel draggable dialog viewer
# ---------------------------------------------------------------------

def display_offline_results(anomalies: List[Dict[str, Any]], container: ui.column) -> None:
    """Display offline anomaly analysis results."""
    container.clear()

    if not anomalies:
        with container:
            ui.label('No anomalies detected').classes('text-grey-7')
        return

    with container:
        with ui.card().classes('w-full q-pa-md'):
            ui.label(f'Analysis Results: {len(anomalies)} Anomalies Found')\
              .classes('text-h6 text-weight-bold q-mb-md')

            # -----------------------------------------------------------------
            # Group by category
            # -----------------------------------------------------------------
            categories: Dict[str, List[Dict[str, Any]]] = {}
            for anomaly in anomalies:
                cat = anomaly.get('category') or 'Uncategorized'
                categories.setdefault(cat, []).append(anomaly)

            details_table: Optional[ui.table] = None

            # -----------------------------------------------------------------
            # Category summary with checkboxes and filtering
            # -----------------------------------------------------------------
            with ui.expansion('Category Summary', icon='category').classes('w-full q-mb-md'):
                checkboxes: Dict[str, ui.checkbox] = {}
                selected_categories = set(categories.keys())

                def apply_filter() -> None:
                    if details_table is None:
                        return
                    filtered = [
                        a for a in anomalies
                        if a.get('category') in selected_categories
                    ]
                    details_table.rows = filtered
                    details_table.update()

                # Individual category checkboxes, sorted by anomaly count
                for category, items in sorted(
                    categories.items(),
                    key=lambda x: len(x[1]),
                    reverse=True,
                ):
                    with ui.row().classes('items-center justify-between w-full'):
                        cb = ui.checkbox(category, value=True)
                        checkboxes[category] = cb
                        ui.badge(str(len(items))).props('color=negative')

                        def make_handler(cat: str, cbox: ui.checkbox):
                            def _on_change():
                                if cbox.value:
                                    selected_categories.add(cat)
                                else:
                                    selected_categories.discard(cat)
                                apply_filter()
                            return _on_change

                        cb.on('update:model-value', make_handler(category, cb))

                # Select-all control
                with ui.row().classes('items-center justify-between w-full q-mt-sm'):
                    select_all_cb = ui.checkbox('Select All', value=True)
                    ui.badge(str(len(anomalies))).props('color=primary')

                    def on_select_all() -> None:
                        if select_all_cb.value:
                            selected_categories.update(categories.keys())
                            for c in checkboxes.values():
                                c.value = True
                        else:
                            selected_categories.clear()
                            for c in checkboxes.values():
                                c.value = False
                        apply_filter()

                    select_all_cb.on('update:model-value', on_select_all)

            # -----------------------------------------------------------------
            # Anomaly details table
            # -----------------------------------------------------------------
            anomaly_columns = [
                {'name': 'file',        'label': 'File',      'field': 'file',        'align': 'left'},
                {'name': 'device',      'label': 'Device',    'field': 'device',      'align': 'left'},
                {'name': 'line',        'label': 'Line',      'field': 'line',        'align': 'left'},
                {'name': 'line_number', 'label': 'Line #',    'field': 'line_number', 'align': 'left'},
                {'name': 'category',    'label': 'Category',  'field': 'category',    'align': 'left'},
                {'name': 'timestamp',   'label': 'Timestamp', 'field': 'timestamp',   'align': 'left'},
                {'name': 'log_line',    'label': 'Log Line',  'field': 'line',        'align': 'left'},
                {'name': 'actions',     'label': 'Actions',   'field': 'file',        'align': 'left'},
            ]

            details_table = ui.table(
                columns=anomaly_columns,
                rows=anomalies,
                row_key='timestamp',
            ).classes('w-full')

            # Add view button slot; emit the whole row payload
            details_table.add_slot('body-cell-actions', r"""
                <q-td :props="props" auto-width>
                  <q-btn dense flat color="primary" icon="visibility" label="View"
                         @click="() => $parent.$emit('view-anomaly', props.row)" />
                </q-td>
            """)

            # Simple file cache to avoid rereads
            _file_cache: Dict[str, List[str]] = {}

            def _get_file_lines(path: str) -> List[str]:
                if path not in _file_cache:
                    try:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                            _file_cache[path] = fh.read().splitlines()
                    except Exception:
                        _file_cache[path] = []
                return _file_cache[path]

            # Track dialog stacking & positions
            _dialog_count = 0

            def handle_view_anomaly(e) -> None:
                """Handle view-anomaly button clicks (parallel draggable dialog)."""
                nonlocal _dialog_count

                try:
                    # Get row data from event
                    row_data = e.args if hasattr(e, 'args') else None
                    if not isinstance(row_data, dict):
                        ui.notify('Unable to open anomaly details – no row data.', type='warning')
                        return

                    file_path = row_data.get('full_path') or row_data.get('file')
                    line_no = row_data.get('line_number', 1)

                    if not file_path or not os.path.exists(file_path):
                        ui.notify('Original log file not found on disk.', type='negative')
                        return

                    try:
                        line_no = int(line_no)
                    except Exception:
                        line_no = 1

                    # Force unique dialog id
                    dialog_id = str(uuid.uuid4())
                    offset_x = (_dialog_count * 50) % 300
                    offset_y = (_dialog_count * 40) % 200
                    _dialog_count += 1

                    # Local vars for dialog
                    current_file = file_path
                    lines = _get_file_lines(file_path)
                    total = len(lines)
                    current_target_line = max(1, min(line_no, total if total > 0 else 1))

                    # Create dialog with unique id, non-blocking
                    detail_dialog = ui.dialog().props(
                        f'persistent seamless id=anomaly-dialog-{dialog_id}'
                    )

                    # ---------------------- Z-INDEX MANAGEMENT JS ----------------------
                    ui.run_javascript(f"""
                        if (typeof window.lastZIndex === 'undefined') {{
                            window.lastZIndex = 9000;
                        }}
                        function activateDialog(dialogId) {{
                            window.lastZIndex += 100;
                            const dialog = document.getElementById('anomaly-dialog-' + dialogId);
                            if (!dialog) return;
                            const card = dialog.querySelector('.q-card');
                            if (!card) return;
                            card.style.zIndex = window.lastZIndex;
                        }}
                        window.activateDialog = activateDialog;
                        activateDialog('{dialog_id}');
                    """)

                    # ---------------------- DRAGGABLE CARD JS -------------------------
                    ui.run_javascript(f"""
                        (function() {{
                            const dialog = document.getElementById('anomaly-dialog-{dialog_id}');
                            if (!dialog) return;
                            const card = dialog.querySelector('.q-card');
                            if (!card) return;

                            let isDragging = false;
                            let currentX, currentY;
                            let initialX, initialY;
                            let xOffset = {50 + offset_x};
                            let yOffset = {50 + offset_y};

                            card.style.position = 'fixed';
                            card.style.left = xOffset + 'px';
                            card.style.top = yOffset + 'px';

                            if (!window.dialogPositions) window.dialogPositions = {{}};
                            window.dialogPositions['{dialog_id}'] = {{x: xOffset, y: yOffset}};

                            function dragStart(e) {{
                                window.activateDialog('{dialog_id}');
                                if (e.target.closest('.q-btn') ||
                                    e.target.closest('input') ||
                                    e.target.closest('textarea')) return;

                                const pos = window.dialogPositions['{dialog_id}'] || {{x: xOffset, y: yOffset}};
                                xOffset = pos.x;
                                yOffset = pos.y;

                                if (e.type === 'touchstart') {{
                                    initialX = e.touches[0].clientX - xOffset;
                                    initialY = e.touches[0].clientY - yOffset;
                                }} else {{
                                    initialX = e.clientX - xOffset;
                                    initialY = e.clientY - yOffset;
                                }}

                                if (e.target === card || e.target.closest('.text-h6')) {{
                                    isDragging = true;
                                    card.style.cursor = 'grabbing';
                                }}
                            }}

                            function dragEnd() {{
                                initialX = currentX;
                                initialY = currentY;
                                isDragging = false;
                                card.style.cursor = 'move';
                            }}

                            function drag(e) {{
                                if (!isDragging) return;
                                e.preventDefault();

                                if (e.type === 'touchmove') {{
                                    currentX = e.touches[0].clientX - initialX;
                                    currentY = e.touches[0].clientY - initialY;
                                }} else {{
                                    currentX = e.clientX - initialX;
                                    currentY = e.clientY - initialY;
                                }}

                                const maxX = window.innerWidth - card.offsetWidth;
                                const maxY = window.innerHeight - card.offsetHeight;
                                xOffset = Math.max(0, Math.min(currentX, maxX));
                                yOffset = Math.max(0, Math.min(currentY, maxY));

                                card.style.left = xOffset + 'px';
                                card.style.top = yOffset + 'px';

                                if (!window.dialogPositions) window.dialogPositions = {{}};
                                window.dialogPositions['{dialog_id}'] = {{x: xOffset, y: yOffset}};
                            }}

                            card.addEventListener('mousedown', dragStart, false);
                            document.addEventListener('mouseup',   dragEnd,   false);
                            document.addEventListener('mousemove', drag,      false);
                            card.addEventListener('touchstart',    dragStart, false);
                            document.addEventListener('touchend',  dragEnd,   false);
                            document.addEventListener('touchmove', drag,      false);
                        }})();
                    """)

                    # ---------------------- DIALOG CONTENT ----------------------------
                    def _render_context(center_line: int,
                                        lines_before: int = 20,
                                        lines_after: int = 20,
                                        highlight_line: Optional[int] = None) -> None:
                        nonlocal current_target_line

                        if not lines:
                            return

                        total_lines = len(lines)
                        center_line_clamped = max(1, min(center_line, total_lines))
                        current_target_line = center_line_clamped

                        start = max(1, center_line_clamped - lines_before)
                        end = min(total_lines, center_line_clamped + lines_after)

                        from html import escape as _esc
                        parts: List[str] = []

                        # inline CSS for log viewer
                        style = """
<style>
.log-viewer {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace;
  white-space: pre;
  background: #0b0f19;
  color: #e5e7eb;
  padding: 12px;
  border-radius: 8px;
  max-height: 600px;
  overflow: auto;
  border: 1px solid #1f2937;
}
.log-line { display: block; }
.log-line-target { background:#374151; color:#fbbf24; }
</style>
"""
                        parts.append(style)
                        parts.append(
                            f"<div class='text-caption text-grey-5 q-mb-sm'>"
                            f"Showing lines {start}-{end} of {total_lines} "
                            f"(±{lines_before}/{lines_after} around target)</div>"
                        )
                        parts.append("<div class='log-viewer'>")

                        width = len(str(end))
                        for idx in range(start, end + 1):
                            text = lines[idx - 1]
                            ln = str(idx).rjust(width)
                            cls = 'log-line'
                            if highlight_line is None:
                                if idx == current_target_line:
                                    cls = 'log-line log-line-target'
                            else:
                                if idx == highlight_line:
                                    cls = 'log-line log-line-target'
                            parts.append(
                                f"<span class='{cls}'>{_esc(ln)}: {_esc(text)}</span>"
                            )

                        parts.append('</div>')

                        html_content = ''.join(parts)
                        log_html.set_content(html_content)

                    with detail_dialog:
                        with ui.card().classes(
                            'w-[1100px] max-w-[95vw] q-pa-md relative'
                        ).style(
                            f'position: fixed; top: {50 + offset_y}px; left: {50 + offset_x}px'
                        ) as dialog_card:

                            # drag handle is basically the header row
                            with ui.row().classes('items-center justify-between w-full q-mb-sm'):
                                ui.label(os.path.basename(current_file)).classes(
                                    'text-h6 text-weight-bold q-mr-sm'
                                )
                                ui.label(f'Line {current_target_line}').classes('text-caption')

                                ui.button('Close', on_click=detail_dialog.close).props(
                                    'flat dense round color=negative'
                                )

                            log_html = ui.html().classes('w-full')

                            # initial render
                            _render_context(current_target_line)

                    detail_dialog.open()

                except Exception as ex:
                    print(f'Error in handle_view_anomaly: {ex}')
                    ui.notify('Error opening anomaly details.', type='negative')

            # Bind view-anomaly event
            details_table.on('view-anomaly', handle_view_anomaly)

            # Export button
            with ui.row().classes('q-mt-md'):
                ui.button(
                    'Export to JSON',
                    on_click=lambda: export_anomalies(details_table.rows),
                    icon='download',
                ).props('outline')
# ---------------------------------------------------------------------
# Helper functions for file / anomaly utilities
# ---------------------------------------------------------------------

def extract_device_name(file_path: str) -> str:
    """Extract device name from file path."""
    basename = os.path.basename(file_path)
    name = os.path.splitext(basename)[0]
    return name


def clear_live_anomalies(table: ui.table) -> None:
    """Clear live anomaly table."""
    table.rows = []
    table.update()
    ui.notify('Anomalies cleared', type='info')


def export_anomalies(anomalies: List[Dict[str, Any]]) -> None:
    """Export anomalies to JSON file."""
    if not anomalies:
        ui.notify('No anomalies to export', type='warning')
        return

    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'anomalies_{timestamp}.json'
        json_data = json.dumps(anomalies, indent=2)
        ui.download(json_data.encode('utf-8'), filename=filename)
        ui.notify(f'Exported {len(anomalies)} anomalies to {filename}', type='positive')
    except Exception as e:
        ui.notify(f'Export failed: {e}', type='negative')


def save_anomalies_to_json(anomalies: List[Dict[str, Any]]) -> str:
    """Save anomalies to a JSON file on disk and return the path."""
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        # Ensure logs directory exists
        out_dir = os.path.join('logs')
        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception:
            # fallback to current directory
            out_dir = '.'

        filename = f'offline_anomalies_{timestamp}.json'
        path = os.path.join(out_dir, filename)
        with open(path, 'w', encoding='utf-8') as out:
            json.dump(anomalies, out, indent=2)
        return os.path.abspath(path)
    except Exception:
        # If saving fails, return a placeholder path
        return 'save_failed.json'

# ---------------------------------------------------------
# MAIN PAGE
# ---------------------------------------------------------

@ui.page("/")
def main_page():
    """Main page that creates the anomaly detection interface"""

    # Add CSS for styling
    ui.add_head_html("""
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Inter', sans-serif;
            background-color: #F5F5F5;
        }
        .header-title {
            font-weight: 700;
            font-size: 1.5rem;
            color: #0ea5e9;
        }
        .text-caption {
            font-size: 0.75rem;
            color: #666;
        }
    </style>
    """)
    # ----------------------
    # Header
    # ----------------------
    with ui.header().classes("q-pa-md bg-white shadow-1"):
        with ui.row().classes("w-full items-center justify-between"):
            ui.label("Anomaly Detection Tool").classes("header-title")

    # ----------------------
    # Create Anomaly Page
    # ----------------------
    create_anomaly_page()

    # ----------------------
    # Footer
    # ----------------------
    with ui.footer().classes("q-pa-sm bg-white shadow-1"):
        with ui.row().classes("w-full items-center justify-between"):
            ui.label("Anomaly Detection Tool - Standalone Version").classes("text-caption")
            ui.label("Powered by NiceGUI").classes("text-caption")

# ---------------------------------------------------------
# RUN APP
# ---------------------------------------------------------

if __name__ == "__main__":
    ui.run(
        title="Anomaly Detection Tool",
        reload=False,   # faster reload
        show=False,     # don't auto-open browser
        port=8080,
        favicon=None,

        # Performance tweaks
        binding_refresh_interval=0.5,
        reconnect_timeout=30.0,
    )