from __future__ import annotations
from nicegui import ui
from typing import Dict, List, Tuple, Any, Optional, Iterable
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
    r"Crashdump magic": "CRASH_DUMP",
    r"Call Trace": "CALL_TRACE",
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
    # WiFi Specific Issues
    r"vap_down": "VAP_DOWN",
    r"Received CSA": "CHANNEL_SWITCH",
    r"Invalid beacon report": "BEACON_REPORT_ISSUE",

    # Resource Issues
    r"Resource manager crash": "RESOURCE_MANAGER_CRASH",
    # RCU and Timing Issues
    r"timeout waiting": "TIMEOUT",

    # Warnings
    r"CPU:\d+ WARNING": "CPU_WARNING",
}
# -----------------------------------------------------
# Anomaly detector
# -----------------------------------------------------

class AnomalyDetector:
    """Optimized anomaly detection engine with batch processing"""

    def __init__(self):
        self.patterns: Dict[str, str] = DEFAULT_ANOMALY_PATTERNS.copy()
        self.custom_patterns: Dict[str, str] = {}
        self.compiled_patterns: Dict[re.Pattern, str] = {}

        # Cache for combined regex pattern
        self._combined_pattern = None
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
                compiled[re.compile(pattern, re.IGNORECASE)] = category
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

    def _detect_from_lines(self, lines: Iterable[str]) -> List[Dict[str, Any]]:
        """Core anomaly detection that works on any line iterable (streaming-friendly)."""
        if not self._patterns_compiled:
            self._compile_patterns()

        anomalies: List[Dict[str, Any]] = []
        ts = datetime.now().isoformat()

        # Use combined pattern for faster matching if available
        if self._combined_pattern and self._pattern_map:
            pattern = self._combined_pattern
            group_map = self._pattern_map

            for line_num, line in enumerate(lines, start=1):
                if not line:
                    continue
                stripped = line.strip()
                if not stripped:
                    continue

                match = pattern.search(stripped)
                if match:
                    for group_name, category in group_map.items():
                        if match.group(group_name):
                            anomalies.append(
                                {
                                    "line_number": line_num,
                                    "line": stripped,
                                    "pattern": match.group(group_name),
                                    "category": category,
                                    "timestamp": ts,
                                }
                            )
                            break  # Only record first match per line
        else:
            compiled_patterns = self.compiled_patterns
            for line_num, line in enumerate(lines, start=1):
                if not line:
                    continue
                stripped = line.strip()
                if not stripped:
                    continue

                for pat, category in compiled_patterns.items():
                    if pat.search(stripped):
                        anomalies.append(
                            {
                                "line_number": line_num,
                                "line": stripped,
                                "pattern": pat.pattern,
                                "category": category,
                                "timestamp": ts,
                            }
                        )
                        break  # Only record first match per line

        return anomalies
    def detect_anomalies(self, log_text: str) -> List[Dict[str, Any]]:
        """Backward-compatible API for callers who pass a single string."""
        return self._detect_from_lines(log_text.splitlines())
    
    def categorize_anomalies(
                            self,
                            anomalies: List[Dict[str, Any]],
                            testplan_name: str = None,
                            testcase_name: str = None,
                            device_name: str = None,
                        ) -> Dict[str, List[Dict[str, Any]]]:
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
        offline_tab = ui.tab("Offline Anomaly", icon="folder_open")
        live_tab = ui.tab("Live Anomaly", icon="sensors")
        

    # Tab Panels
    with ui.tab_panels(tabs, value=live_tab).classes("w-full"):
        # ------------------ OFFLINE TAB ------------------
        with ui.tab_panel(offline_tab):
            create_offline_anomaly_tab()

        # ------------------ LIVE TAB ------------------
        with ui.tab_panel(live_tab):
            create_live_anomaly_tab()

        
def create_live_anomaly_tab():

    # Create the Live Anomaly Detection Tab
    with ui.column().classes("w-full q-gutter-md"):
        ui.label("Live Anomaly Detection").classes("text-h6 text-weight-bold")
        ui.label(
            "Monitor real-time device logs for anomalies during test execution"
        ).classes("text-body2 text-grey-7")

    # ---------------------------------------------------------------------
    # Pattern Management Section
    # ---------------------------------------------------------------------
        with ui.card().classes("w-full q-pa-md"):
            ui.label("Pattern Management").classes(
                "text-subtitle1 text-weight-bold q-mb-sm"
            )
            ui.label(
                "Manage anomaly detection patterns – upload files or edit patterns directly"
            ).classes("text-caption text-grey-7 q-mb-md")

            pattern_status = ui.label(
                f"Using {len(ANOMALY_DETECTOR.patterns)} patterns "
                f"({len(DEFAULT_ANOMALY_PATTERNS)} default + "
                f"{len(ANOMALY_DETECTOR.custom_patterns)} custom)"
            ).classes("text-positive")

            # Pattern management tabs
            with ui.tabs().classes("w-full") as pattern_tabs:
                upload_tab = ui.tab("Upload File", icon="upload_file")
                edit_tab = ui.tab("Edit Patterns", icon="edit")
                export_tab = ui.tab("Export", icon="download")
            # ---------------------------------------------------------------------
            # Upload Tab
            # ---------------------------------------------------------------------
            with ui.tab_panels(pattern_tabs,value=upload_tab).classes("w-full"):
                with ui.tab_panel(upload_tab):
                    ui.label("Upload Exception Pattern File").classes("text-body2 text-weight-bold q-mb-sm")
                    ui.label("Upload a .py file containing exception patterns").classes("text-caption text-grey-7 q-mb-md")
                    def handle_pattern_upload(e):
                        try:
                            # Save uploaded file temporarily
                            content = e.get_uploaded_content()
                            temp_path = "temp_exception_patterns.py"

                            with open(temp_path, "wb") as f:
                                f.write(content)

                            # Load patterns
                            success, message = ANOMALY_DETECTOR.load_pattern_file(temp_path)

                            if success:
                                pattern_status.text = f"✔ {message}"
                                pattern_status.classes("text-positive")

                                ui.notify(message, type="positive")

                                # Refresh pattern editor if it exists
                                if "pattern_table" in locals():
                                    refresh_pattern_table()
                            else:
                                pattern_status.text = f"✘ {message}"
                                pattern_status.classes("text-negative")
                                ui.notify(message, type="negative")

                            # Clean up temp file
                            try:
                                os.remove(temp_path)
                            except:
                                pass

                        except Exception as ex:
                            pattern_status.text = f"✘ Error: {str(ex)}"
                            pattern_status.classes("text-negative")
                            ui.notify(f"Error: {str(ex)}", type="negative")

                    ui.upload(
                        label="Upload Exception Pattern .py File",
                        on_upload=handle_pattern_upload,
                        auto_upload=True,
                    ).props("accept=.py").classes("w-full")
                with ui.tab_panel(edit_tab):
                    ui.label("Pattern Editor").classes("text-body2 text-weight-bold q-mb-sm")
                    ui.label("Add, edit, or delete anomaly detection patterns").classes("text-caption text-grey-7 q-mb-md")
                    # Add new pattern section
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
                                pattern = (new_pattern_input.value or "").strip()
                                category = (new_category_input.value or "").strip()

                                if not pattern or not category:
                                    ui.notify(
                                        "Both pattern and category are required",
                                        type="warning",
                                    )
                                    return

                                # Test if pattern is valid regex
                                try:
                                    re.compile(pattern, re.IGNORECASE)
                                except re.error as ex:
                                    ui.notify(
                                        f"Invalid regex pattern: {str(ex)}",
                                        type="negative",
                                    )
                                    return

                                # Add to custom patterns
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

                                ui.notify(
                                    f"Added pattern: {pattern} -> {category}",
                                    type="positive",
                                )

                            ui.button(
                                "Add Pattern",
                                icon="add",
                                on_click=add_new_pattern,
                            ).props("color=primary")

                    # Pattern table columns
                    pattern_columns = [
                        {"name": "pattern", "label": "Regex Pattern", "field": "pattern", "align": "left"},
                        {"name": "category", "label": "Category", "field": "category", "align": "left"},
                        {"name": "type", "label": "Type", "field": "type", "align": "left"},
                        {"name": "actions", "label": "Actions", "field": "pattern", "align": "left"},
                    ]

                    def get_pattern_rows():
                        rows = []

                        # Add default patterns
                        for pattern, category in DEFAULT_ANOMALY_PATTERNS.items():
                            rows.append({
                                "pattern": pattern,
                                "category": category,
                                "type": "Default",
                                "is_default": True,
                            })

                        # Add custom patterns
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
                    row_key="pattern").classes("w-full")

                    # Add action buttons to pattern table - allow editing of all patterns
                    pattern_table.add_slot("body-cell-actions", r"""
                        <q-td :props="props" auto-width>
                            <q-btn dense flat color='primary' icon='edit'
                                @click.stop.prevent="$parent.$emit('edit-pattern', props.row)" 
                                title="Edit Patern" />
                            <q-btn dense flat color='negative' icon='delete'
                                @click.stop.prevent="$parent.$emit('delete-pattern', props.row)" 
                                title="Delete Patern"/>
                            <q-btn v-if="!props.row.is_default" dense flat color='secondary' icon='content_copy'
                                @click.stop.prevent="$parent.$emit('copy-pattern', props.row)" 
                                title="Copy to Custom"/>
                        </q-td>
                    """)

                    def refresh_pattern_table():
                        pattern_table.rows = get_pattern_rows()
                        pattern_table.update()

                    # Edit pattern dialog
                    edit_dialog = ui.dialog()

                    def show_edit_dialog(pattern_data):
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
                                    ui.button(
                                        "Cancel",
                                        on_click=edit_dialog.close,
                                    ).props("flat")

                                    def save_edit():
                                        old_pattern = pattern_data["pattern"]
                                        new_pattern = edit_pattern_input.value.strip()
                                        new_category = edit_category_input.value.strip()

                                        if not new_pattern or not new_category:
                                            ui.notify(
                                                "Both pattern and category are required",
                                                type="warning",
                                            )
                                            return

                                        # Test if pattern is valid regex
                                        try:
                                            re.compile(new_pattern, re.IGNORECASE)
                                        except re.error as ex:
                                            ui.notify(
                                                f"Invalid regex pattern: {str(ex)}",
                                                type="negative",
                                            )
                                            return

                                        # Add / update as custom pattern
                                        if old_pattern in ANOMALY_DETECTOR.custom_patterns:
                                            del ANOMALY_DETECTOR.custom_patterns[old_pattern]
                                        if old_pattern in ANOMALY_DETECTOR.patterns:
                                            del ANOMALY_DETECTOR.patterns[old_pattern]

                                        ANOMALY_DETECTOR.custom_patterns[new_pattern] = new_category
                                        ANOMALY_DETECTOR.patterns[new_pattern] = new_category

                                        ANOMALY_DETECTOR._compile_patterns()

                                        # Refresh displays
                                        pattern_status.text = (
                                            f"Using {len(ANOMALY_DETECTOR.patterns)} patterns "
                                            f"({len(DEFAULT_ANOMALY_PATTERNS)} default + "
                                            f"{len(ANOMALY_DETECTOR.custom_patterns)} custom)"
                                        )
                                        refresh_pattern_table()
                                        ui.notify(
                                            f"Saved pattern: {new_pattern} ({new_category})",
                                            type="positive",
                                        )
                                        edit_dialog.close()

                                    ui.button(
                                        "Save",
                                        on_click=save_edit,
                                    ).props("color=primary")
                        edit_dialog.open()
                    def handle_edit_pattern(e):
                        row_data = e.args if hasattr(e, "args") else None
                        if row_data:
                            def show_full_edit_dialog(pattern_data):
                                edit_dialog.clear()
                                with edit_dialog:
                                    with ui.card().classes("w-96 q-pa-md"):
                                        ui.label("Edit Pattern").classes("text-h6 text-weight-bold q-mb-md")

                                        edit_pattern_input = ui.input(
                                            "Regex Pattern", value=pattern_data["pattern"]
                                        ).classes("w-full q-mb-sm")

                                        edit_category_input = ui.input(
                                            "Category", value=pattern_data["category"]
                                        ).classes("w-full q-mb-md")

                                        with ui.row().classes("w-full justify-end q-gutter-sm"):
                                            ui.button(
                                                "Cancel",
                                                on_click=edit_dialog.close
                                            ).props("flat")

                                            def save_edit():
                                                old_pattern = pattern_data["pattern"]
                                                new_pattern = edit_pattern_input.value.strip()
                                                new_category = edit_category_input.value.strip()
                                                is_default = pattern_data.get("is_default", False)

                                                if not new_pattern or not new_category:
                                                    ui.notify(
                                                        "Both pattern and category are required",
                                                        type="warning"
                                                    )
                                                    return

                                                # Test if pattern is valid regex
                                                try:
                                                    re.compile(new_pattern, re.IGNORECASE)
                                                except re.error as ex:
                                                    ui.notify(
                                                        f"Invalid regex pattern: {str(ex)}",
                                                        type="negative"
                                                    )
                                                    return

                                                if is_default:
                                                    # Editing a default pattern
                                                    global DEFAULT_ANOMALY_PATTERNS
                                                    DEFAULT_ANOMALY_PATTERNS = dict(DEFAULT_ANOMALY_PATTERNS)

                                                    if old_pattern in DEFAULT_ANOMALY_PATTERNS:
                                                        del DEFAULT_ANOMALY_PATTERNS[old_pattern]

                                                    DEFAULT_ANOMALY_PATTERNS[new_pattern] = new_category

                                                    # Sync detector patterns
                                                    ANOMALY_DETECTOR.patterns = {
                                                        **DEFAULT_ANOMALY_PATTERNS,
                                                        **ANOMALY_DETECTOR.custom_patterns
                                                    }

                                                    ui.notify(
                                                        f"Edited default pattern: {new_pattern} ({new_category})",
                                                        type="positive"
                                                    )

                                                else:
                                                    # Editing a custom pattern
                                                    if old_pattern in ANOMALY_DETECTOR.custom_patterns:
                                                        del ANOMALY_DETECTOR.custom_patterns[old_pattern]

                                                    if old_pattern in ANOMALY_DETECTOR.patterns:
                                                        del ANOMALY_DETECTOR.patterns[old_pattern]

                                                    ANOMALY_DETECTOR.custom_patterns[new_pattern] = new_category
                                                    ANOMALY_DETECTOR.patterns[new_pattern] = new_category

                                                    ui.notify(
                                                        f"Edited custom pattern: {new_pattern} ({new_category})",
                                                        type="positive"
                                                    )

                                                ANOMALY_DETECTOR._compile_patterns()

                                                pattern_status.text = (
                                                    f"Using {len(ANOMALY_DETECTOR.patterns)} patterns "
                                                    f"({len(DEFAULT_ANOMALY_PATTERNS)} default + "
                                                    f"{len(ANOMALY_DETECTOR.custom_patterns)} custom)"
                                                )

                                                refresh_pattern_table()
                                                edit_dialog.close()

                                            ui.button(
                                                "Save",
                                                on_click=save_edit
                                            ).props("color=primary")

                                edit_dialog.open()
                            show_full_edit_dialog(row_data)
                        # Bind table event
                        # pattern_table.on("edit-pattern", handle_edit_pattern)
                    def handle_delete_pattern(e):
                        row_data = e.args if hasattr(e, "args") else None
                        if  row_data:
                            pattern = row_data["pattern"]
                            is_default = row_data.get("is_default", False)

                            if is_default:
                                # Delete from the defaults
                                global DEFAULT_ANOMALY_PATTERNS
                                DEFAULT_ANOMALY_PATTERNS = dict(DEFAULT_ANOMALY_PATTERNS)
                                if pattern in DEFAULT_ANOMALY_PATTERNS:
                                    del DEFAULT_ANOMALY_PATTERNS[pattern]

                                # Update detector patterns as well
                                ANOMALY_DETECTOR.patterns = {
                                    **DEFAULT_ANOMALY_PATTERNS,
                                    **ANOMALY_DETECTOR.custom_patterns,
                                }
                                ui.notify(
                                    f"Deleted default pattern: {pattern}",
                                    type="positive",
                                )
                            else:
                                # Remove from custom patterns
                                if pattern in ANOMALY_DETECTOR.custom_patterns:
                                    del ANOMALY_DETECTOR.custom_patterns[pattern]
                                if pattern in ANOMALY_DETECTOR.patterns:
                                    del ANOMALY_DETECTOR.patterns[pattern]

                                ui.notify(
                                    f"Deleted custom pattern: {pattern}",
                                    type="positive",
                                )

                            ANOMALY_DETECTOR._compile_patterns()
                            pattern_status.text = (
                                f"Using {len(ANOMALY_DETECTOR.patterns)} patterns "
                                f"({len(DEFAULT_ANOMALY_PATTERNS)} default + "
                                f"{len(ANOMALY_DETECTOR.custom_patterns)} custom)"
                            )
                            refresh_pattern_table()

                    def handle_copy_pattern(e):
                        row_data = e.args if hasattr(e, "args") else None
                        if  row_data:
                            pattern = row_data["pattern"]
                            category = row_data["category"]

                            # Add to custom patterns
                            ANOMALY_DETECTOR.custom_patterns[pattern] = category
                            ANOMALY_DETECTOR._compile_patterns()

                            # Refresh displays
                            pattern_status.text = (
                                f"Using {len(ANOMALY_DETECTOR.patterns)} patterns "
                                f"({len(DEFAULT_ANOMALY_PATTERNS)} default + "
                                f"{len(ANOMALY_DETECTOR.custom_patterns)} custom)"
                            )
                            refresh_pattern_table()
                            ui.notify(
                                f"Copied pattern to custom: {pattern}",
                                type="positive",
                            )

                    pattern_table.on("edit-pattern", handle_edit_pattern)
                    pattern_table.on("delete-pattern", handle_delete_pattern)
                    pattern_table.on("copy-pattern", handle_copy_pattern)

                with ui.tab_panel(export_tab):
                    ui.label("Export Patterns").classes("text-body2 text-weight-bold q-mb-sm")
                    ui.label("Export current patterns to a Python file").classes("text-caption text-grey-7 q-mb-md")

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
        # ------------------------------------------------------------------
        # Live anomaly display / manual log testing
        # ------------------------------------------------------------------
        with ui.card().classes("w-full q-pa-md"):
            ui.label("Detected anomalies").classes(
                "text-subtitle1 text-weight-bold q-mb-sm"
            )
            ui.label(
                "Anomalies will appear here when detected in log files"
            ).classes("text-caption text-grey-7 q-mb-md")

            # Expansion panel for manual log testing
            with ui.expansion(
                "Test with Log Input", icon="text_snippet"
            ).classes("w-full q-mb-md"):

                ui.label("Paste log text to test anomaly detection").classes(
                    "text-caption text-grey-7 q-mb-sm"
                )

                log_input = ui.textarea(
                    "Log Text",
                    placeholder="Paste log text here...",
                ).classes("w-full").props("rows=4")

                def analyze_log_text():
                    log_text = log_input.value or ""
                    if not log_text.strip():
                        ui.notify(
                            "Please enter log text to analyze", type="warning"
                        )
                        return

                    anomalies = ANOMALY_DETECTOR.detect_anomalies(log_text)

                    if not anomalies:
                        ui.notify(
                            "No anomalies detected in the provided log text",
                            type="info",
                        )
                        return

                    # Format anomalies for display
                    formatted_anomalies = []
                    for anomaly in anomalies:
                        formatted_anomalies.append({
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "testplan": "Manual Test",
                            "testcase": "Log Analysis",
                            "device": "Manual Input",
                            "category": anomaly.get("category"),
                            "line": anomaly["line"],
                        })

                    # Update the table
                    anomaly_table.rows = formatted_anomalies
                    anomaly_table.update()

                    ui.notify(
                        f"Detected {len(anomalies)} anomalies", type="positive"
                    )

                ui.button(
                    "Analyze Log",
                    icon="search",
                    on_click=analyze_log_text,
                ).props("color=primary")

            # ------------------------------------------------------------------
            # Anomaly table columns
            # ------------------------------------------------------------------
            anomaly_columns = [
                {"name": "timestamp", "label": "Timestamp",
                "field": "timestamp", "align": "left"},
                {"name": "testplan", "label": "Testplan",
                "field": "testplan", "align": "left"},
                {"name": "testcase", "label": "Testcase",
                "field": "testcase", "align": "left"},
                {"name": "device", "label": "Device",
                "field": "device", "align": "left"},
                {"name": "category", "label": "Category",
                "field": "category", "align": "left"},
                {"name": "line", "label": "Log Line",
                "field": "line", "align": "left"},
                {"name": "actions", "label": "Actions",
                "field": "actions", "align": "left"},
            ]
            anomaly_table = ui.table(
                columns=anomaly_columns,
                rows=[],
                row_key="timestamp"
            ).classes("w-full")

            # Add view button to emit row payload
            anomaly_table.add_slot("body-cell-actions", """
                <q-td :props="props" auto-width>
                    <q-btn dense flat color='primary' icon='visibility' label='View'
                        @click="$parent.$emit('view-anomaly', props.row)" />
                </q-td>
            """)

            # Handle the view-anomaly event
            def handle_live_view_anomaly(e):
                """Handle view anomaly button clicks for live anomalies"""
                try:
                    import uuid

                    # Get row data from event
                    row_data = e.args if hasattr(e, 'args') else None

                    if not isinstance(row_data, dict):
                        ui.notify("Unable to open anomaly details - no row data.", type="warning")
                        return

                    # Extract fields
                    line = row_data.get("line")
                    category = row_data.get("category")
                    device = row_data.get("device")
                    timestamp = row_data.get("timestamp")
                    dialog_id = str(uuid.uuid4())

                    # Create dialog with unique identifier
                    detail_dialog = ui.dialog().props(f"persistent seamless id=anomaly-dialog-{dialog_id}")

                    with detail_dialog:
                        card = ui.card().classes("w-[700px] max-w-[95vw] q-pa-md").style(
                            "z-index:1000; cursor: move; position: fixed; top: 50px; left: 50px;"
                        )

                        with card:
                            ui.label("Anomaly Detail").classes("text-h6 text-weight-bold q-mb-md")

                            with ui.column().classes("w-full q-gutter-sm"):
                                with ui.row().classes("items-center"):
                                    ui.icon("event").classes("q-mr-xs")
                                    ui.label(f"Timestamp: {timestamp}").classes("text-body2")

                                with ui.row().classes("items-center"):
                                    ui.icon("schedule").classes("q-mr-xs")
                                    ui.label(f"Category: {category}").classes("text-body2")

                                with ui.row().classes("items-center"):
                                    ui.icon("devices").classes("q-mr-xs")
                                    ui.label(f"Device: {device}").classes("text-body2")
                                ui.separator()
                                ui.label("Log Line:").classes("text-body2 text-weight-bold")
                                with ui.card().classes("q-pa-sm bg-grey-2"):
                                    ui.label(line).classes("text-body2 text-mono")
                            with ui.row().classes("justify-end q-mt-md"):
                                ui.button("Close", on_click=detail_dialog.close).props("color=primary")

                    ui.run_javascript(f'''  
                    (function() {{
                        const dialog = document.getElementById('anomaly-dialog');
                        if (!dialog) return;

                        const card = dialog.querySelector('.q-card');
                        if (!card) return;

                        let isDragging = false;
                        let currentX = 0;
                        let currentY = 0;
                        let initialX = 0;
                        let initialY = 0;
                        let xOffset = 50;
                        let yOffset = 50;

                        function dragStart(e) {{
                            if (e.target.closest('.q-btn') || 
                                e.target.closest('input') || 
                                e.target.closest('textarea')) {{
                                return;
                            }}

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

                        function dragEnd(e) {{
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

                            xOffset = currentX;
                            yOffset = currentY;

                            // Keep dialog within viewport bounds
                            const maxX = window.innerWidth - card.offsetWidth;
                            const maxY = window.innerHeight - card.offsetHeight;

                            xOffset = Math.max(0, Math.min(xOffset, maxX));
                            yOffset = Math.max(0, Math.min(yOffset, maxY));

                            card.style.left = xOffset + "px";
                            card.style.top = yOffset + "px";
                        }}

                        card.addEventListener('mousedown', dragStart, false);
                        card.addEventListener('mouseup', dragEnd, false);
                        card.addEventListener('mousemove', drag, false);

                        card.addEventListener('touchstart', dragStart, false);
                        card.addEventListener('touchend', dragEnd, false);
                        card.addEventListener('touchmove', drag, false);
                    }})();
                ''')

                # Open detailed dialog
                    detail_dialog.open()
                except Exception as e:
                    ui.notify(f"Error opening anomaly details: {e}", type="negative")

            # Bind the event for the table
            anomaly_table.on("view-anomaly", handle_live_view_anomaly)
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
                    offline_pattern_table.add_slot('body-cell-actions',r"""
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
                        """)

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
                                with ui.row().classes("w-full justify-end q-gutter-sm"):
                                    ui.button("Cancel", on_click=offline_edit_dialog.close).props("flat")
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
                                    ui.button('Save',on_click=save_edit,).props('color=primary')                           
                                    
                        offline_edit_dialog.open()
                    def handle_offline_edit_pattern(e):
                        row_data = e.args if hasattr(e, 'args') else None
                        if row_data:
                            show_offline_edit_dialog(row_data)
                    def handle_offline_delete_pattern(e):
                        row_data = e.args if hasattr(e, 'args') else None
                        if row_data: 
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
                                ui.notify(f'Deleted pattern: {pattern}', type='positive')
                            ANOMALY_DETECTOR._compile_patterns()
                            pattern_status.text = (
                                f"Using {len(ANOMALY_DETECTOR.patterns)} patterns "
                                f"({len(DEFAULT_ANOMALY_PATTERNS)} default + "
                                f"{len(ANOMALY_DETECTOR.custom_patterns)} custom)"
                            )
                            refresh_offline_pattern_table()                        
                    def handle_offline_copy_pattern(e) -> None:
                        row_data = e.args if hasattr(e, 'args') else None
                        if row_data:
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
                    offline_pattern_table.on('delete-pattern', handle_offline_delete_pattern)
                    offline_pattern_table.on('copy-pattern', handle_offline_copy_pattern)

                # ----------------- Export tab ------------------
                with ui.tab_panel(export_tab):
                    ui.label("Export Patterns").classes("text-body2 text-weight-bold q-mb-sm")
                    ui.label("Export current patterns to a Python file").classes("text-caption text-grey-7 q-mb-md")
                    def export_patterns():
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
                    def export_custom_only():
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

            def analyze_folder():
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
                async def analyze_async():
                    """Async worker for offline log analysis"""
                    import asyncio
                    import concurrent.futures
                    loop = asyncio.get_running_loop()   
                    # helper for single file
                    def _analyze_file(log_file: str):
                        if analysis_state['should_abort']:
                            return []

                        import time as _time
                        start_time = _time.time()
                        try:
                            # network path check (for perf message)
                            is_network_path = log_file.startswith('\\\\') or log_file.startswith('//')

                            size_start = _time.time()
                            file_size = os.path.getsize(log_file)
                            size_time = _time.time() - size_start

                            file_info = (
                                f"Analyzing {log_file} (file_size = {file_size / 1024 / 1024:.1f} MB)"
                            )
                            print(file_info)

                            # STREAMING read + analysis in one pass
                            analyze_start = _time.time()
                            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                                if analysis_state['should_abort']:
                                    print(f"Aborted before analyzing {os.path.basename(log_file)}")
                                    return [], None, None

                                # use streaming line iterator
                                anomalies = ANOMALY_DETECTOR._detect_from_lines(f)
                            analyze_time = _time.time() - analyze_start
                            read_time = 0.0  # merged into analyze_time

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
                                    f"total={total_time:.2f}s, analyze={analyze_time:.2f}s"
                                )
                                print(perf_info)

                            return anomalies, file_info, perf_info
                        except Exception as e:
                            elapsed = time.time() - start_time
                            error_msg = f"Error analyzing {log_file} after {elapsed:.2f}s: {e}"
                            print(error_msg)
                            return [], None, error_msg
                            

                    # ------------- concurrent execution setup -------------
                    cpu_count = os.cpu_count() or 2
                    max_workers = min(cpu_count * 3, len(log_files), 16)
                    completed = 0
                    all_anomalies: List[Dict[str, Any]] = []
                    batch_size = 5  # reduced for more frequent UI updates

                    client_disconnected = False
                    last_successful_update = 0
                    perf_msg = None

                    loop = asyncio.get_running_loop()

                    try:
                        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
                            pending_tasks= []
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
                                    #timeout=60.0
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
                                if not analysis_state['should_abort'] and file_index < len(log_files):
                                    task = loop.run_in_executor(ex, _analyze_file, log_files[file_index])
                                    pending_tasks.append(task)
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
                                        if progress.client.has_socket_connection:
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
                        if client_disconnected:
                            print(
                                f"Analysis completed in background: "
                                f"{len(all_anomalies)} anomalies found in "
                                f"{completed}/{len(log_files)} files"
                            )
                            print(
                                f"Last successful UI update was at "
                                f"{last_successful_update}/{len(log_files)} files"
                            )
                        if analysis_state['should_abort']:
                            print(f"Analysis aborted: Processed {completed} /{len(all_anomalies)} files, found {len(all_anomalies)} anomalies")

                    # always show results, even if client disconnected / aborted
                    try:
                        if progress.client.has_socket_connection:
                            progress.value = 1.0
                            progress.update()
                            await asyncio.sleep(0)

                        with progress_container:
                            progress_container.clear()
                        with results_container:
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
                # kick off async analysis
                import asyncio as _asyncio
                _asyncio.create_task(analyze_async())

            def abort_analysis():
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
    
def display_offline_results(anomalies: List[Dict[str, Any]], container: ui.column):
    """Display offline anomaly analysis results"""
    container.clear()

    if not anomalies:
        with container:
            ui.label("No anomalies detected").classes("text-grey-7")
        return

    with container:
        with ui.card().classes("w-full q-pa-md"):
            ui.label(f"Analysis Results: {len(anomalies)} Anomalies Found").classes(
                "text-h6 text-weight-bold q-mb-md"
            )

            # Group by category
            categories = {}
            for anomaly in anomalies:
                cat = anomaly["category"]
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(anomaly)
            # Category summary with checkboxes and filtering
            # Keep a reference for the details table to allow dynamic filtering
            details_table = None

            # Build interactive category selection
            with ui.expansion("Category Summary", icon="category").classes("w-full q-mb-md"):
                checkboxes = {}
                selected_categories = set(categories.keys())
                is_programmatic_select_all = False  # guard to avoid recursive event storms

                def apply_filter():
                    """Apply current category selection to details table."""
                    if details_table is None:
                        return
                    filtered = [
                        a for a in anomalies
                        if a.get("category") in selected_categories
                    ]
                    details_table.rows = filtered
                    details_table.update()

                # Select All control
                with ui.row().classes("items-center justify-between w-full q-mb-sm"):
                    select_all_cb = ui.checkbox("Select All", value=True)
                    ui.badge(str(len(anomalies))).props("color-primary")

                def on_select_all(e):
                    nonlocal selected_categories, is_programmatic_select_all
                    # If this change was triggered programmatically from child checkboxes,
                    # do NOT run the full select-all logic again.
                    if is_programmatic_select_all:
                        return

                    # NiceGUI usually passes the new value in e.args or via .value
                    if hasattr(e, "args") and isinstance(e.args, bool):
                        val = e.args
                    elif hasattr(e, "value"):
                        val = e.value
                    else:
                        val = bool(select_all_cb.value)

                    if val:
                        # Select all categories
                        selected_categories = set(categories.keys())
                    else:
                        # Deselect all categories
                        selected_categories.clear()

                    # Sync individual checkboxes
                    for cat, cb in checkboxes.items():
                        is_programmatic_select_all = True
                        cb.value = val
                        cb.update()
                        is_programmatic_select_all = False

                    apply_filter()

                select_all_cb.on("update:model-value", on_select_all)

                # Individual category checkboxes
                for category, items in sorted(categories.items(), key=lambda x: len(x[1]), reverse=True):
                    with ui.row().classes("items-center justify-between w-full"):
                        with ui.row().classes("items-center"):
                            cb = ui.checkbox(category, value=True)
                            checkboxes[category] = cb
                        ui.badge(str(len(items))).props("color-negative")

                    def make_handler(cat, cbox):
                        def _on_change(e):
                            nonlocal is_programmatic_select_all

                            # Update selected_categories based on this single checkbox
                            if cbox.value:
                                selected_categories.add(cat)
                            else:
                                selected_categories.discard(cat)

                            # Maintain Select All visual state, but avoid triggering its logic
                            all_selected = len(selected_categories) == len(categories)
                            if select_all_cb.value != all_selected:
                                is_programmatic_select_all = True
                                select_all_cb.value = all_selected
                                select_all_cb.update()
                                is_programmatic_select_all = False

                            apply_filter()
                        return _on_change

                    cb.on("update:model-value", make_handler(category, cb))

            # Detailed table (initially show all anomalies; filtering will adjust rows)
            anomaly_columns = [
                {"name": "file", "label": "File", "field": "file", "align": "left"},
                {"name": "device", "label": "Device", "field": "device", "align": "left"},
                {"name": "line_number", "label": "Line", "field": "line_number", "align": "left"},
                {"name": "category", "label": "Category", "field": "category", "align": "left"},
                {"name": "log_line", "label": "Log Line", "field": "line", "align": "left"},
                {"name": "actions", "label": "Actions", "field": "file", "align": "left"},
            ]

            details_table = ui.table(
                columns=anomaly_columns,
                rows=anomalies,
                row_key="timestamp",
            ).classes("w-full")

            # Add view button to emit row payload
            details_table.add_slot("body-cell-actions", r"""
                <q-td :props="props" auto-width>
                    <q-btn dense flat color="primary" icon="visibility" label="View"
                        @click="$parent.$emit('view-anomaly', props.row)" />
                </q-td>
            """)
            # details_table.add_slot("body-cell-actions", r"""
            #     <q-td props="props" auto-width>
            #         <q-btn dense flat color="primary" icon="visibility" label="View"
            #             @click="() => $parent.emit('view-anomaly', props.row)" />
            #     </q-td>
            # """)
            # Cache to avoid rereads
            _file_cache = {}

            def _get_file_lines(path: str):
                if path not in _file_cache:
                    try:
                        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                            _file_cache[path] = fh.read().splitlines()
                    except Exception:
                        _file_cache[path] = []
                return _file_cache[path], len(_file_cache[path])

            # Track dialog stacking positions
            _dialog_count = 0
            """Handle view anomaly button clicks (parallel dialog)"""
            def handle_view_anomaly(e):
                nonlocal _dialog_count
                try:
                    # Import uuid
                    import uuid

                    # Get row data from event
                    row_data = e.args if hasattr(e, "args") else None

                    if not isinstance(row_data, dict):
                        ui.notify("Unable to open anomaly details - no row data.", type="warning")
                        return

                    file_path = row_data.get("full_path")
                    line_no = row_data.get("line_number", 1)

                    if not file_path or not os.path.exists(file_path):
                        ui.notify("Original log file not found on disk.", type="negative")
                        return
                    try:
                        line_no = int(line_no)
                    except Exception:
                        line_no = 1

                    # Force unique dialog (parallel)
                    dialog_id = str(uuid.uuid4())
                    offset_x = (_dialog_count * 50) % 300
                    offset_y = (_dialog_count * 40) % 200
                    _dialog_count += 1

                    # Local vars for dialog
                    current_file = file_path
                    lines, total = _get_file_lines(file_path)
                    current_total = total
                    current_target_line = max(1, min(line_no, total if total > 0 else 1))
                    log_html = None
                    go_to_number = None

                    # Create dialog with unique id, non-blocking
                    detail_dialog = ui.dialog().props(f"persistent seamless id=anomaly-dialog-{dialog_id}")

                    # CRITICAL: Define the z-index management function FIRST
                    ui.run_javascript(
                        f"""
                    // CRITICAL FIX: Define global z-index management
                    if (typeof window.lastZIndex === 'undefined') {{
                        window.lastZIndex = 9000;
                    }}

                    function activateDialog(dialogId) {{
                        console.log("Activating dialog: " + dialogId);
                        window.lastZIndex += 100;
                        const dialog = document.getElementById("anomaly-dialog-" + dialogId);
                        if (dialog) {{
                            const card = dialog.querySelector(".q-card");
                            if (card) {{
                                console.log("Setting z-index to: " + window.lastZIndex);
                                card.style.zIndex = window.lastZIndex;
                            }}
                        }}
                    }}

                    // Make it globally available
                    window.activateDialog = activateDialog;

                    // Immediately activate this dialog
                    activateDialog("{dialog_id}");
                    """
                    )
                    # ----------------------------------------------------------------------
                # CONTEXT RENDERING FUNCTION
                # ----------------------------------------------------------------------
                    def _render_context(center_line: int, lines_before: int = 20, lines_after: int = 20, highlight_line: Optional[int] = None):
                        nonlocal log_html, current_file, current_target_line

                        if not current_file:
                            return

                        lines, total = _get_file_lines(current_file)
                        if total <= 0:
                            log_html.set_content("<div class='text-negative'>Failed to read file content.</div>")
                            return
                        clamped=False
                        # Clamp center line
                        if center_line < 1:
                            center_line = 1
                            clamped=True
                        if center_line > total:
                            center_line = total
                            clamped=True
                        start = max(1, center_line - lines_before)
                        end = min(total, center_line + lines_after)
                        current_target_line = center_line                      
                        if go_to_number is not None:
                            # Update go-to max value
                            try:
                                go_to_number.props(f"min=1 max={total} step=1")
                            except:
                                pass
                        from html import escape as _esc
                        parts = []
                        ln_width = len(str(end))

                        # CSS at top of viewer
                        parts.append("""
                        <style>
                        .log-viewer {
                            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace;
                            white-space: pre;
                            background: #0b0f19;
                            color: #e5e7eb;
                            padding: 12px;
                            border-radius: 8px;
                            max-height: 600px;
                            overflow:auto;
                            border: 1px solid #192937;
                        }
                        .log-ln { display:block; color:#9ca3af; }
                        .log-target { background:#374151; color:#ffebba; }
                        </style>
                        """)

                        # Header info
                        parts.append(
                            f"<div class='text-caption text-grey-5 q-mb-sm'>Showing lines {start}-{end} of {total} "
                            f"({lines_before}/{lines_after} around target)</div>"
                        )

                        parts.append("<div class='log-viewer'>")

                        for idx in range(start - 1, end):
                            text = _esc(lines[idx])
                            num = idx + 1
                            is_target = (highlight_line == num)

                            if is_target:
                                parts.append(
                                    f"<span class='log-ln log-target'><span class='cls'>{num:{ln_width}d}</span> {text}</span>"
                                )
                            else:
                                parts.append(
                                    f"<span class='log-ln'><span class='cls'>{num:{ln_width}d}</span> {text}</span>"
                                )

                        parts.append("</div>")

                        html_content = "\n".join(parts)
                        if log_html:
                            log_html.set_content(html_content)
                        if clamped:
                            ui.notify("Required line out of range;window clamped to file boundaries.", type='info')
                    with detail_dialog:
                        dialog_card = ui.card().classes("w-[1100px] max-w-[95vw] q-pa-md relative").style(
                            f"position: fixed; top: {50 + offset_y}px; left: {50 + offset_x}px; z-index: 9999; cursor: move;"
                        )

                        # ❗CRITICAL: Add click handler to bring dialog to front
                        ui.run_javascript(
                            f"""
                            document.getElementById("anomaly-dialog-{dialog_id}")
                                .querySelector(".q-card")
                                .addEventListener("mousedown", function() {{
                                    window.activateDialog("{dialog_id}");
                                }});
                            """
                        )

                        with dialog_card:
                            with ui.row().classes("items-center justify-between w-full q-mb-sm"):
                                ui.label(f"Anomaly Details: {os.path.basename(current_file)}").classes("text-h6 text-weight-bold")

                                with ui.row().classes("items-center q-gutter-xs"):
                                    ui.button(
                                        icon="minimize",
                                        on_click=lambda: ui.run_javascript(
                                            f'minimizeDialog("{dialog_id}")'
                                        ),
                                    ).props("flat dense round size=sm").tooltip("Minimize")
                                    ui.button(
                                        icon="crop_square",
                                        on_click=lambda: ui.run_javascript(
                                            f'maximizeDialog("{dialog_id}")'
                                        ),
                                    ).props("flat dense round size=sm").tooltip("Maximize/Restore")
                                    ui.button(
                                        icon="close",
                                        on_click=detail_dialog.close,
                                    ).props("flat dense round size=sm color=negative").tooltip("Close")
                            dialog_content = ui.column().classes("w-full")
                            with dialog_content:
                            # File location
                                with ui.row().classes("items-center q-gutter-sm q-mb-xs"):
                                    ui.icon("insert_drive_file").classes("text-grey-7")
                                    ui.label(os.path.basename(file_path)).classes("text-body2")
                                    ui.separator().props("vertical").classes("q-mx-sm")
                                    ui.icon("format_list_numbered").classes("text-grey-7")
                                    ui.label(f"Lines: {total}").classes("text-caption text-grey-7")
                                    ui.separator().props("vertical").classes("q-mx-sm")
                                    ui.icon("my_location")
                                    ui.label(f"Target line: {current_target_line}").classes("text-body2")
                                # Line number navigation
                                with ui.row().classes("items-center q-gutter-sm q-mb-sm"):
                                    ui.label("Go to line").classes("text-caption text-grey-7")

                                    # Input for go-to line
                                    go_to_number = ui.input(label="go to line",value=str(current_target_line)).props("type=number dense outlined")
                                    lines_before_input = (
                                        ui.input("Lines before", value="20")
                                        .props("type=number dense outlined min=0 max=500 step=1")
                                        .classes("w-28")
                                    )

                                    lines_after_input = (
                                        ui.input("Lines after", value="20")
                                        .props("type=number dense outlined min=0 max=500 step=1")
                                        .classes("w-28") )
                                    def _submit_go_to():
                                        nonlocal current_target_line
                                        # Parse and validate line number
                                        val = go_to_number.value if go_to_number is not None else ""
                                        try:
                                            num = int(float(val))
                                        except Exception:
                                            ui.notify("Please enter a valid numeric line number.", type="warning")
                                            return

                                        if current_total <= 0:
                                            ui.notify("Log file is empty or unreadable.", type="warning")
                                            return
                                        clamped_num = max(1, min(num, current_total))
                                        if clamped_num != num:
                                            ui.notify(
                                                f"Target line clamped to {clamped_num} "
                                                "(outside of range).",
                                                type="info",
                                            )

                                        current_target_line = clamped_num
                                        try:
                                            lines_before = int(float(lines_before_input.value or "20"))
                                            lines_after = int(float(lines_after_input.value or "20"))
                                        except ValueError:
                                            lines_before, lines_after = 20, 20
                                        _render_context(current_target_line,lines_before=lines_before,lines_after=lines_after,highlight_line=current_target_line)

                                        # CRITICAL: Update active dialog z-index
                                        ui.run_javascript(f"window.activateDialog('{dialog_id}')")
                                    def _update_content():
                                        try:
                                            lines_before = int(float(lines_before_input.value or "20"))
                                            lines_after = int(float(lines_after_input.value or "20"))
                                        except ValueError:
                                            lines_before, lines_after = 20, 20
                                        _render_context(current_target_line,lines_before=lines_before,lines_after=lines_after,highlight_line=current_target_line)
                                        ui.run_javascript(f"window.activateDialog('{dialog_id}')")
                                    lines_before_input.on('blur',_update_content)
                                    lines_after_input.on('blur',_update_content)
                                    ui.button("Go",icon="play_arrow",on_click=_submit_go_to).props("color=primary")
                                    ui.button("Refresh",icon="refresh",on_click=_update_content).props("outline").tooltip("Update context view")
                                    # HTML Log View
                                log_html = ui.html("",sanitize=False).classes("q-mt-md w-full")
                        ui.run_javascript("""
                        // Define window control functions globally if not already defined
                        if (!window.minimizeDialog) {
                            window.minimizeDialog = function (dialogId) {
                                const dialog = document.getElementById('anomaly-dialog-' + dialogId);
                                if (!dialog) return;

                                const card = dialog.querySelector('.q-card');
                                if (!card) return;

                                // Store current size before minimizing
                                if (!card.dataset.originalHeight) {
                                    card.dataset.originalHeight = card.offsetHeight + 'px';
                                    card.datase
                                    t.originalWidth  = card.offsetWidth  + 'px';
                                }

                                // Toggle minimized state
                                if (card.dataset.minimized === 'true') {
                                    // Restore from minimized
                                    const content = card.querySelectorAll('.q-card > div:not(:first-child)');
                                    content.forEach(el => el.style.display = 'block');

                                    card.style.height = card.dataset.wasMaximized === 'true'
                                        ? '80vh'
                                        : (card.dataset.originalHeight || 'auto');

                                    card.dataset.minimized = 'false';
                                } else {
                                    // Minimize
                                    const content = card.querySelectorAll('.q-card > div:not(:first-child)');
                                    content.forEach(el => el.style.display = 'none');

                                    card.dataset.wasMaximized = card.dataset.maximized || 'false';
                                    card.style.height = '60px';
                                    card.dataset.minimized = 'true';
                                    card.dataset.maximized = 'false';
                                }

                                // CRITICAL: Activate dialog after minimizing
                                window.activateDialog(dialogId);
                            };

                            window.maximizeDialog = function (dialogId) {
                                const dialog = document.getElementById('anomaly-dialog-' + dialogId);
                                if (!dialog) return;

                                const card = dialog.querySelector('.q-card');
                                if (!card) return;

                                // Store original size/position if not already stored
                                if (!card.dataset.originalHeight) {
                                    card.dataset.originalHeight = card.offsetHeight + 'px';
                                    card.dataset.originalWidth  = card.offsetWidth  + 'px';
                                    card.dataset.originalLeft   = card.style.left;
                                    card.dataset.originalTop    = card.style.top;
                                }

                                // Toggle maximized state
                                if (card.dataset.maximized === 'true') {
                                    // Restore from maximized
                                    card.style.width  = card.dataset.originalWidth  || '1100px';
                                    card.style.height = card.dataset.originalHeight || 'auto';
                                    card.style.left   = card.dataset.originalLeft   || '50px';
                                    card.style.top    = card.dataset.originalTop    || '50px';
                                    card.dataset.maximized = 'false';
                                } else {
                                    // Maximize
                                    card.dataset.minimized = 'false';

                                    const content = card.querySelectorAll('.q-card > div:not(:first-child)');
                                    content.forEach(el => el.style.display = 'block');

                                    card.style.width  = '80vw';
                                    card.style.height = '80vh';
                                    card.style.left   = '10vw';
                                    card.style.top    = '10vh';
                                    card.dataset.maximized = 'true';
                                }

                                // CRITICAL: Activate dialog after maximizing
                                window.activateDialog(dialogId);
                            };
                        }
                        """)
                        ui.run_javascript(f"""
                        (function() {{
                            const dialog = document.getElementById('anomaly-dialog-{dialog_id}');
                            if (!dialog) return;
                            const card = dialog.querySelector('.q-card');
                            if (!card) return;

                            if (!window.dialogPositions) window.dialogPositions = {{}};
                            if (!window.dialogPositions['{dialog_id}']) {{
                                window.dialogPositions['{dialog_id}'] = {{x: 50, y: 50}};
                            }}

                            let isDragging = false;
                            let currentX = 0;
                            let currentY = 0;
                            let initialX = 0;
                            let initialY = 0;
                            let xOffset = window.dialogPositions['{dialog_id}'].x;
                            let yOffset = window.dialogPositions['{dialog_id}'].y;

                            // Apply last known position
                            card.style.left = xOffset + "px";
                            card.style.top = yOffset + "px";

                            function dragStart(e) {{
                                if (e.target.closest('.q-btn') ||
                                    e.target.closest('input') ||
                                    e.target.closest('textarea')) {{
                                    return;
                                }}

                                if (e.type === "touchstart") {{
                                    initialX = e.touches[0].clientX - xOffset;
                                    initialY = e.touches[0].clientY - yOffset;
                                }} else {{
                                    initialX = e.clientX - xOffset;
                                    initialY = e.clientY - yOffset;
                                }}

                                if (e.target === card || e.target.closest('.text-h6')) {{
                                    isDragging = true;
                                    card.style.cursor = "grabbing";
                                }}
                            }}

                            function dragEnd(e) {{
                                initialX = currentX;
                                initialY = currentY;
                                isDragging = false;
                                card.style.cursor = "move";
                            }}

                            function drag(e) {{
                                if (!isDragging) return;
                                e.preventDefault();

                                if (e.type === "touchmove") {{
                                    currentX = e.touches[0].clientX - initialX;
                                    currentY = e.touches[0].clientY - initialY;
                                }} else {{
                                    currentX = e.clientX - initialX;
                                    currentY = e.clientY - initialY;
                                }}

                                // Update position
                                const maxX = window.innerWidth - card.offsetWidth;
                                const maxY = window.innerHeight - card.offsetHeight;
                                xOffset = Math.max(0, Math.min(currentX, maxX));
                                yOffset = Math.max(0, Math.min(currentY, maxY));

                                card.style.left = xOffset + "px";
                                card.style.top = yOffset + "px";

                                // CRITICAL: Update our global position variable during drag
                                window.dialogPositions['{dialog_id}'].x = xOffset;
                                window.dialogPositions['{dialog_id}'].y = yOffset;
                            }}

                            card.addEventListener("mousedown", dragStart, false);
                            document.addEventListener("mouseup", dragEnd, false);
                            document.addEventListener("mousemove", drag, false);

                            card.addEventListener("touchstart", dragStart, false);
                            card.addEventListener("touchend", dragEnd, false);
                            card.addEventListener("touchmove", drag, false);
                        }})();
                    """)
                    detail_dialog.open()
                    _render_context(current_target_line,lines_before=20,lines_after=20,highlight_line=current_target_line)
                except Exception as ex:
                    print(f"Error in handle_view_anomaly: {ex}")
                    ui.notify("Error opening anomaly details.", type="negative")
            details_table.on("view-anomaly", handle_view_anomaly)
            # Export button row
            with ui.row().classes("q-mt-md"):
                ui.button(
                    "Export to JSON",
                    on_click=lambda: export_anomalies(details_table.rows),
                    icon="download",
                ).props("outline")
                        

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
        #out_dir = os.path.join('logs')
        out_dir = "C:/Amomaly_logs"
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
    except Exception as e:
        # If saving fails, return a placeholder path
        return f"save_failed: {e}"

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
        reconnect_timeout=300.0,
    )