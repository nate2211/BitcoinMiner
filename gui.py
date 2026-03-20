from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from PyQt5.QtCore import QThread, Qt, pyqtSignal
from PyQt5.QtGui import QCloseEvent, QFont, QTextCursor
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from btc_models import BtcMinerConfig
from btc_opencl_scanner import OpenCLSha256dScanner
from btc_worker import BitcoinMinerWorker


CONFIG_FILENAME = "bitcoin_gui_config.json"
LOGS_DIRNAME = "logs"


def _module_dir() -> Path:
    return Path(__file__).resolve().parent


def _exe_dir() -> Path:
    return Path(sys.executable).resolve().parent


def _cwd_dir() -> Path:
    return Path.cwd().resolve()


def _meipass_dir() -> Optional[Path]:
    meipass = getattr(sys, "_MEIPASS", None)
    if not meipass:
        return None
    try:
        return Path(meipass).resolve()
    except Exception:
        return None


def _unique_paths(paths: list[Path]) -> list[Path]:
    out: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path).lower()
        if key not in seen:
            seen.add(key)
            out.append(path)
    return out


def _resource_candidates(name_or_path: str) -> list[Path]:
    raw = (name_or_path or "").strip()
    if not raw:
        return []

    p = Path(raw)
    if p.is_absolute():
        return [p.resolve()]

    paths: list[Path] = [
        _exe_dir() / raw,
        _cwd_dir() / raw,
        _module_dir() / raw,
    ]
    meipass = _meipass_dir()
    if meipass is not None:
        paths.append(meipass / raw)
    return _unique_paths(paths)


def _resolve_resource(name_or_path: str, default_name: str) -> str:
    raw = (name_or_path or "").strip() or default_name
    candidates = _resource_candidates(raw)
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    if candidates:
        return str(candidates[0])
    return str(_exe_dir() / default_name)


def _config_load_candidates() -> list[Path]:
    paths: list[Path] = [
        _exe_dir() / CONFIG_FILENAME,
        _cwd_dir() / CONFIG_FILENAME,
        _module_dir() / CONFIG_FILENAME,
    ]
    meipass = _meipass_dir()
    if meipass is not None:
        paths.append(meipass / CONFIG_FILENAME)
    return _unique_paths(paths)


def _config_save_candidates() -> list[Path]:
    paths: list[Path] = [
        _exe_dir() / CONFIG_FILENAME,
        _cwd_dir() / CONFIG_FILENAME,
        _module_dir() / CONFIG_FILENAME,
    ]
    meipass = _meipass_dir()
    if meipass is not None:
        paths.append(meipass / CONFIG_FILENAME)
    return _unique_paths(paths)


def _is_writable_target(path: Path) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        test_file = path.parent / ".bitcoin_cfg_write_test"
        test_file.write_text("ok", encoding="utf-8")
        test_file.unlink(missing_ok=True)
        return True
    except Exception:
        return False


def _resolve_load_config_path() -> Optional[Path]:
    for candidate in _config_load_candidates():
        if candidate.exists():
            return candidate
    return None


def _resolve_save_config_path() -> Path:
    for candidate in _config_save_candidates():
        if _is_writable_target(candidate):
            return candidate
    return _cwd_dir() / CONFIG_FILENAME


def _logs_dir() -> str:
    candidates = [
        _exe_dir() / LOGS_DIRNAME,
        _cwd_dir() / LOGS_DIRNAME,
        _module_dir() / LOGS_DIRNAME,
    ]
    meipass = _meipass_dir()
    if meipass is not None:
        candidates.append(meipass / LOGS_DIRNAME)

    for candidate in _unique_paths(candidates):
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            test_file = candidate / ".logs_write_test"
            test_file.write_text("ok", encoding="utf-8")
            test_file.unlink(missing_ok=True)
            return str(candidate)
        except Exception:
            pass

    fallback = _cwd_dir() / LOGS_DIRNAME
    fallback.mkdir(parents=True, exist_ok=True)
    return str(fallback)


CONFIG_PATH = _resolve_save_config_path()


class StatCard(QFrame):
    def __init__(self, title: str, value: str = "-", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("StatCard")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(5)

        self.title_label = QLabel(title)
        self.title_label.setObjectName("CardTitle")

        self.value_label = QLabel(value)
        self.value_label.setObjectName("CardValue")
        self.value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)

        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)

    def set_value(self, text: str) -> None:
        self.value_label.setText(text)


class MinerThread(QThread):
    log_signal = pyqtSignal(str)
    status_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, config: BtcMinerConfig) -> None:
        super().__init__()
        self.config = config
        self.worker: Optional[BitcoinMinerWorker] = None

    def run(self) -> None:
        try:
            self.worker = BitcoinMinerWorker(
                self.config,
                on_log=self.log_signal.emit,
                on_status=self.status_signal.emit,
            )
            self.worker.run()
        except Exception as exc:
            self.log_signal.emit(f"[gui] worker crashed: {exc}")
            self.status_signal.emit("error")
        finally:
            self.finished_signal.emit()

    def request_stop(self) -> None:
        if self.worker is not None:
            self.worker.stop()


class BitcoinMinerWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()

        self.thread: Optional[MinerThread] = None
        self.log_lines: list[str] = []

        self.accepted_count = 0
        self.rejected_count = 0
        self.last_job_id = "-"
        self.last_nonce = "-"
        self.current_status = "idle"

        self.setWindowTitle("Bitcoin Miner Control Panel")
        self.resize(1620, 980)
        self.setMinimumSize(1240, 760)

        self._build_ui()
        self._apply_dark_theme()
        self._load_config()
        self._refresh_devices(initial=True)
        self._sync_button_state(running=False)

    def _build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)

        outer = QVBoxLayout(root)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(10)

        outer.addWidget(self._build_header(), 0)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        self.left_scroll = self._build_left_panel()
        self.right_tabs = self._build_right_panel()

        splitter.addWidget(self.left_scroll)
        splitter.addWidget(self.right_tabs)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([420, 1180])

        outer.addWidget(splitter, 1)

    def _build_header(self) -> QWidget:
        frame = QFrame()
        frame.setObjectName("HeaderFrame")

        layout = QHBoxLayout(frame)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(12)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)

        title = QLabel("Bitcoin Miner Control Panel")
        title.setObjectName("AppTitle")

        subtitle = QLabel("Large log workspace with a compact control bar at the bottom of the settings panel.")
        subtitle.setObjectName("AppSubtitle")

        title_col.addWidget(title)
        title_col.addWidget(subtitle)

        layout.addLayout(title_col, 1)

        self.header_status_label = QLabel("IDLE")
        self.header_status_label.setObjectName("StatusBadge")
        self.header_status_label.setAlignment(Qt.AlignCenter)
        self.header_status_label.setMinimumWidth(120)

        layout.addWidget(self.header_status_label, 0, Qt.AlignRight | Qt.AlignVCenter)
        return frame

    def _build_left_panel(self) -> QWidget:
        container = QWidget()
        outer = QVBoxLayout(container)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(10)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setObjectName("SettingsScrollArea")

        content = QWidget()
        content.setObjectName("SettingsPane")

        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        layout.addWidget(self._build_status_group())
        layout.addWidget(self._build_pool_group())
        layout.addWidget(self._build_backend_group())
        layout.addWidget(self._build_opencl_group())
        layout.addWidget(self._build_runtime_group())
        layout.addStretch(1)

        scroll.setWidget(content)

        outer.addWidget(scroll, 1)
        outer.addWidget(self._build_bottom_button_bar(), 0)

        return container

    def _build_right_panel(self) -> QTabWidget:
        tabs = QTabWidget()
        tabs.setObjectName("MainTabs")

        tabs.addTab(self._build_log_tab(), "Live Log")
        tabs.addTab(self._build_overview_tab(), "Overview")

        return tabs

    def _build_status_group(self) -> QWidget:
        group = QGroupBox("Session")
        layout = QVBoxLayout(group)
        layout.setSpacing(10)

        row = QHBoxLayout()
        row.setSpacing(8)

        self.side_status_value = QLabel("idle")
        self.side_status_value.setObjectName("InlineValue")

        self.side_scanner_value = QLabel("-")
        self.side_scanner_value.setObjectName("InlineValue")

        row.addWidget(QLabel("Status:"))
        row.addWidget(self.side_status_value, 1)
        row.addWidget(QLabel("Scanner:"))
        row.addWidget(self.side_scanner_value, 1)

        layout.addLayout(row)
        return group

    def _build_bottom_button_bar(self) -> QWidget:
        frame = QFrame()
        frame.setObjectName("BottomBar")

        layout = QHBoxLayout(frame)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(8)

        self.start_button = QPushButton("Start")
        self.start_button.setObjectName("PrimaryButton")

        self.stop_button = QPushButton("Stop")
        self.stop_button.setObjectName("DangerButton")

        self.save_cfg_button = QPushButton("Save Config")
        self.save_log_button = QPushButton("Save Log")
        self.clear_log_button = QPushButton("Clear Log")

        self.start_button.clicked.connect(self._start_miner)
        self.stop_button.clicked.connect(self._stop_miner)
        self.save_cfg_button.clicked.connect(self._save_config)
        self.save_log_button.clicked.connect(self._save_log)
        self.clear_log_button.clicked.connect(self._clear_log)

        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)
        layout.addStretch(1)
        layout.addWidget(self.save_cfg_button)
        layout.addWidget(self.save_log_button)
        layout.addWidget(self.clear_log_button)

        return frame

    def _build_pool_group(self) -> QWidget:
        group = QGroupBox("Pool / Stratum")
        form = QFormLayout(group)
        form.setLabelAlignment(Qt.AlignRight)
        form.setFormAlignment(Qt.AlignTop)
        form.setSpacing(10)

        self.host_edit = QLineEdit()
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)

        self.login_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.agent_edit = QLineEdit()
        self.use_tls_check = QCheckBox("Use TLS")

        self.login_edit.setPlaceholderText("wallet.worker")
        self.password_edit.setPlaceholderText("x")
        self.agent_edit.setPlaceholderText("OpenCL-BTC/0.2")

        form.addRow("Host:", self.host_edit)
        form.addRow("Port:", self.port_spin)
        form.addRow("Login:", self.login_edit)
        form.addRow("Password:", self.password_edit)
        form.addRow("Agent:", self.agent_edit)
        form.addRow("", self.use_tls_check)

        return group

    def _build_backend_group(self) -> QWidget:
        group = QGroupBox("Backend / Native")
        form = QFormLayout(group)
        form.setLabelAlignment(Qt.AlignRight)
        form.setSpacing(10)

        self.scan_backend_combo = QComboBox()
        self.scan_backend_combo.addItems(["opencl", "native", "python", "auto"])

        self.native_dll_edit = QLineEdit()
        dll_row = QHBoxLayout()
        dll_row.setSpacing(6)
        dll_row.addWidget(self.native_dll_edit, 1)

        dll_browse = QPushButton("Browse")
        dll_browse.clicked.connect(self._browse_native_dll)
        dll_row.addWidget(dll_browse)

        form.addRow("Scan backend:", self.scan_backend_combo)
        form.addRow("Native DLL:", self._wrap_layout(dll_row))
        return group

    def _build_opencl_group(self) -> QWidget:
        group = QGroupBox("OpenCL")
        form = QFormLayout(group)
        form.setLabelAlignment(Qt.AlignRight)
        form.setSpacing(10)

        self.opencl_loader_edit = QLineEdit()
        self.kernel_path_edit = QLineEdit()
        self.build_options_edit = QLineEdit()

        kernel_row = QHBoxLayout()
        kernel_row.setSpacing(6)
        kernel_row.addWidget(self.kernel_path_edit, 1)

        kernel_browse = QPushButton("Browse")
        kernel_browse.clicked.connect(self._browse_kernel)
        kernel_row.addWidget(kernel_browse)

        self.platform_spin = QSpinBox()
        self.platform_spin.setRange(0, 999)

        self.device_spin = QSpinBox()
        self.device_spin.setRange(0, 999)

        self.local_work_size_spin = QSpinBox()
        self.local_work_size_spin.setRange(0, 4096)
        self.local_work_size_spin.setSpecialValueText("auto")

        self.device_combo = QComboBox()
        self.refresh_devices_button = QPushButton("Refresh Devices")
        self.refresh_devices_button.clicked.connect(self._refresh_devices)
        self.device_combo.currentIndexChanged.connect(self._device_selected)

        device_box = QVBoxLayout()
        device_top = QHBoxLayout()
        device_top.setSpacing(6)
        device_top.addWidget(self.device_combo, 1)
        device_top.addWidget(self.refresh_devices_button)
        device_box.addLayout(device_top)

        form.addRow("OpenCL loader:", self.opencl_loader_edit)
        form.addRow("Kernel path:", self._wrap_layout(kernel_row))
        form.addRow("Build options:", self.build_options_edit)
        form.addRow("Detected device:", self._wrap_layout(device_box))
        form.addRow("Platform index:", self.platform_spin)
        form.addRow("Device index:", self.device_spin)
        form.addRow("Local work size:", self.local_work_size_spin)

        return group

    def _build_runtime_group(self) -> QWidget:
        group = QGroupBox("Runtime")
        form = QFormLayout(group)
        form.setLabelAlignment(Qt.AlignRight)
        form.setSpacing(10)

        self.scan_window_spin = QSpinBox()
        self.scan_window_spin.setRange(1, 2_000_000_000)

        self.max_results_spin = QSpinBox()
        self.max_results_spin.setRange(1, 4096)

        self.socket_timeout_spin = QSpinBox()
        self.socket_timeout_spin.setRange(1, 600)

        self.submit_timeout_spin = QSpinBox()
        self.submit_timeout_spin.setRange(1, 600)

        self.idle_sleep_ms_spin = QSpinBox()
        self.idle_sleep_ms_spin.setRange(1, 5000)

        form.addRow("Scan window nonces:", self.scan_window_spin)
        form.addRow("Max results / scan:", self.max_results_spin)
        form.addRow("Socket timeout (s):", self.socket_timeout_spin)
        form.addRow("Submit timeout (s):", self.submit_timeout_spin)
        form.addRow("Idle sleep (ms):", self.idle_sleep_ms_spin)

        return group

    def _build_log_tab(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("Panel")

        layout = QVBoxLayout(panel)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        title = QLabel("Live Logs")
        title.setObjectName("SectionTitle")

        self.autoscroll_check = QCheckBox("Auto-scroll")
        self.autoscroll_check.setChecked(True)

        self.log_filter_edit = QLineEdit()
        self.log_filter_edit.setPlaceholderText("Filter log text...")
        self.log_filter_edit.textChanged.connect(self._rebuild_log_view)

        toolbar.addWidget(title)
        toolbar.addStretch(1)
        toolbar.addWidget(self.autoscroll_check)
        toolbar.addWidget(self.log_filter_edit, 1)

        self.log_edit = QPlainTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setLineWrapMode(QPlainTextEdit.NoWrap)

        mono = QFont("Consolas")
        mono.setStyleHint(QFont.Monospace)
        mono.setPointSize(10)
        self.log_edit.setFont(mono)

        layout.addLayout(toolbar)
        layout.addWidget(self.log_edit, 1)

        return panel

    def _build_overview_tab(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("Panel")

        layout = QVBoxLayout(panel)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        title = QLabel("Overview")
        title.setObjectName("SectionTitle")
        layout.addWidget(title)

        grid = QGridLayout()
        grid.setSpacing(10)

        self.status_card = StatCard("Status", "idle")
        self.backend_card = StatCard("Scanner", "-")
        self.job_card = StatCard("Job ID", "-")
        self.accepted_card = StatCard("Accepted", "0")
        self.rejected_card = StatCard("Rejected", "0")
        self.nonce_card = StatCard("Last Nonce", "-")

        grid.addWidget(self.status_card, 0, 0)
        grid.addWidget(self.backend_card, 0, 1)
        grid.addWidget(self.job_card, 0, 2)
        grid.addWidget(self.accepted_card, 1, 0)
        grid.addWidget(self.rejected_card, 1, 1)
        grid.addWidget(self.nonce_card, 1, 2)

        layout.addLayout(grid)
        layout.addStretch(1)
        return panel

    @staticmethod
    def _wrap_layout(layout) -> QWidget:
        w = QWidget()
        w.setLayout(layout)
        return w

    def _apply_dark_theme(self) -> None:
        self.setStyleSheet(
            """
            QWidget {
                background-color: #11161d;
                color: #e8edf4;
                font-size: 10.5pt;
            }
            QMainWindow {
                background-color: #11161d;
            }
            QFrame#HeaderFrame, QFrame#Panel, QFrame#StatCard, QFrame#BottomBar {
                background-color: #181f28;
                border: 1px solid #273241;
                border-radius: 10px;
            }
            QGroupBox {
                background-color: #181f28;
                border: 1px solid #273241;
                border-radius: 10px;
                margin-top: 14px;
                padding-top: 12px;
                font-weight: 600;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 6px;
                color: #9bc2ff;
            }
            QLabel#AppTitle {
                font-size: 18pt;
                font-weight: 700;
                color: #ffffff;
            }
            QLabel#AppSubtitle {
                color: #aab6c5;
                font-size: 10pt;
            }
            QLabel#SectionTitle {
                font-size: 12pt;
                font-weight: 600;
                color: #ffffff;
            }
            QLabel#CardTitle {
                color: #9fb2c9;
                font-size: 9pt;
                font-weight: 600;
            }
            QLabel#CardValue {
                color: #ffffff;
                font-size: 15pt;
                font-weight: 700;
            }
            QLabel#InlineValue {
                color: #ffffff;
                font-weight: 600;
            }
            QLabel#StatusBadge {
                background-color: #1d2a36;
                border: 1px solid #35516d;
                border-radius: 16px;
                padding: 8px 14px;
                color: #eaf3ff;
                font-weight: 700;
                letter-spacing: 0.5px;
            }
            QLineEdit, QPlainTextEdit, QComboBox, QSpinBox {
                background-color: #0f141a;
                color: #f4f7fb;
                border: 1px solid #334355;
                border-radius: 7px;
                padding: 7px 9px;
                selection-background-color: #2b5ea7;
                selection-color: #ffffff;
            }
            QPlainTextEdit {
                font-size: 10pt;
            }
            QComboBox QAbstractItemView {
                background-color: #131920;
                color: #f4f7fb;
                border: 1px solid #334355;
                selection-background-color: #2b5ea7;
            }
            QPushButton {
                background-color: #233447;
                color: #f5f8fc;
                border: 1px solid #31475e;
                border-radius: 6px;
                padding: 5px 10px;
                min-height: 24px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #2d435a;
            }
            QPushButton:disabled {
                background-color: #202a35;
                color: #7f92a5;
                border: 1px solid #2a3948;
            }
            QPushButton#PrimaryButton {
                background-color: #1f4f8c;
                border: 1px solid #2f68b2;
            }
            QPushButton#PrimaryButton:hover {
                background-color: #2964ad;
            }
            QPushButton#DangerButton {
                background-color: #7f2f3a;
                border: 1px solid #a24451;
            }
            QPushButton#DangerButton:hover {
                background-color: #97414d;
            }
            QCheckBox {
                spacing: 8px;
            }
            QSplitter::handle {
                background-color: #24303d;
            }
            QScrollArea {
                border: none;
                background: transparent;
            }
            QScrollBar:vertical {
                background: #121821;
                width: 12px;
                margin: 2px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background: #3a4a5d;
                min-height: 30px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical:hover {
                background: #50657e;
            }
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QTabWidget::pane {
                border: 1px solid #273241;
                background: #181f28;
                border-radius: 10px;
                top: -1px;
            }
            QTabBar::tab {
                background: #141b23;
                color: #cfd9e6;
                padding: 10px 18px;
                margin-right: 4px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                min-width: 120px;
            }
            QTabBar::tab:selected {
                background: #1f4f8c;
                color: #ffffff;
            }
            QTabBar::tab:hover:!selected {
                background: #223041;
            }
            """
        )

    def _default_config(self) -> BtcMinerConfig:
        return BtcMinerConfig(
            host="btc.hiveon.com",
            port=4444,
            login="bc1yourwallet.worker",
            password="x",
            agent="OpenCL-BTC/0.2",
            use_tls=False,
            scan_backend="opencl",
            native_dll_path=_resolve_resource("", "BitcoinProject.dll"),
            opencl_loader=_resolve_resource("", "OpenCL.dll"),
            kernel_path=_resolve_resource("", "btc_sha256d_scan.cl"),
            build_options="-cl-std=CL1.2",
            platform_index=0,
            device_index=0,
            local_work_size=128,
            scan_window_nonces=1_048_576,
            max_results_per_scan=8,
            socket_timeout_s=60.0,
            submit_timeout_s=15.0,
            idle_sleep_s=0.10,
        )

    def _load_config(self) -> None:
        global CONFIG_PATH

        cfg = self._default_config()

        for candidate in _config_load_candidates():
            if not candidate.exists():
                continue
            try:
                with open(candidate, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                cfg = BtcMinerConfig(**raw)
                CONFIG_PATH = candidate
                break
            except Exception as exc:
                self._append_log(f"[gui] failed to load config from {candidate}: {exc}")

        self._apply_config(cfg)

    def _save_config(self) -> None:
        global CONFIG_PATH

        try:
            cfg = self._collect_config()
            CONFIG_PATH = _resolve_save_config_path()
            CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(asdict(cfg), f, indent=2)
            self._append_log(f"[gui] config saved to {CONFIG_PATH}")
        except Exception as exc:
            QMessageBox.critical(self, "Save Config Failed", str(exc))

    def _apply_config(self, cfg: BtcMinerConfig) -> None:
        self.host_edit.setText(cfg.host)
        self.port_spin.setValue(int(cfg.port))
        self.login_edit.setText(cfg.login)
        self.password_edit.setText(cfg.password)
        self.agent_edit.setText(cfg.agent)
        self.use_tls_check.setChecked(bool(cfg.use_tls))

        self.scan_backend_combo.setCurrentText(cfg.normalized_scan_backend())
        self.native_dll_edit.setText(cfg.native_dll_path)

        self.opencl_loader_edit.setText(cfg.opencl_loader)
        self.kernel_path_edit.setText(cfg.kernel_path)
        self.build_options_edit.setText(cfg.build_options)
        self.platform_spin.setValue(int(cfg.platform_index))
        self.device_spin.setValue(int(cfg.device_index))
        self.local_work_size_spin.setValue(int(cfg.local_work_size or 0))

        self.scan_window_spin.setValue(int(cfg.scan_window_nonces))
        self.max_results_spin.setValue(int(cfg.max_results_per_scan))
        self.socket_timeout_spin.setValue(int(round(cfg.socket_timeout_s)))
        self.submit_timeout_spin.setValue(int(round(cfg.submit_timeout_s)))
        self.idle_sleep_ms_spin.setValue(int(round(cfg.idle_sleep_s * 1000.0)))

    def _collect_config(self) -> BtcMinerConfig:
        local_work_size = int(self.local_work_size_spin.value())
        return BtcMinerConfig(
            host=self.host_edit.text().strip(),
            port=int(self.port_spin.value()),
            login=self.login_edit.text().strip(),
            password=self.password_edit.text().strip() or "x",
            agent=self.agent_edit.text().strip() or "OpenCL-BTC/0.2",
            use_tls=self.use_tls_check.isChecked(),
            scan_backend=self.scan_backend_combo.currentText(),
            native_dll_path=self.native_dll_edit.text().strip(),
            opencl_loader=self.opencl_loader_edit.text().strip(),
            kernel_path=self.kernel_path_edit.text().strip(),
            build_options=self.build_options_edit.text().strip(),
            platform_index=int(self.platform_spin.value()),
            device_index=int(self.device_spin.value()),
            local_work_size=None if local_work_size <= 0 else local_work_size,
            scan_window_nonces=int(self.scan_window_spin.value()),
            max_results_per_scan=int(self.max_results_spin.value()),
            socket_timeout_s=float(self.socket_timeout_spin.value()),
            submit_timeout_s=float(self.submit_timeout_spin.value()),
            idle_sleep_s=float(self.idle_sleep_ms_spin.value()) / 1000.0,
        )

    def _refresh_devices(self, initial: bool = False) -> None:
        current_text = self.device_combo.currentText()
        self.device_combo.blockSignals(True)
        self.device_combo.clear()

        try:
            devices = OpenCLSha256dScanner.list_devices()
            for item in devices:
                label = f"P{item.platform_index}/D{item.device_index} - {item.platform_name} / {item.device_name}"
                self.device_combo.addItem(label, (item.platform_index, item.device_index))
        except Exception as exc:
            self.device_combo.addItem("OpenCL device enumeration failed", (-1, -1))
            if not initial:
                self._append_log(f"[gui] OpenCL device refresh failed: {exc}")

        self.device_combo.blockSignals(False)

        if current_text:
            idx = self.device_combo.findText(current_text)
            if idx >= 0:
                self.device_combo.setCurrentIndex(idx)

        if self.device_combo.count() > 0 and self.device_combo.currentIndex() < 0:
            self.device_combo.setCurrentIndex(0)

        self._device_selected(self.device_combo.currentIndex())

    def _device_selected(self, index: int) -> None:
        data = self.device_combo.itemData(index)
        if not isinstance(data, tuple) or len(data) != 2:
            return
        platform_index, device_index = data
        if platform_index >= 0:
            self.platform_spin.setValue(int(platform_index))
        if device_index >= 0:
            self.device_spin.setValue(int(device_index))

    def _start_miner(self) -> None:
        if self.thread is not None and self.thread.isRunning():
            return

        try:
            cfg = self._collect_config()
        except Exception as exc:
            QMessageBox.critical(self, "Invalid Configuration", str(exc))
            return

        if not cfg.login:
            QMessageBox.warning(self, "Missing Login", "Enter your pool login in wallet.worker form.")
            return
        if not cfg.host:
            QMessageBox.warning(self, "Missing Host", "Enter a Stratum host.")
            return

        self.accepted_count = 0
        self.rejected_count = 0
        self.last_job_id = "-"
        self.last_nonce = "-"
        self.current_status = "starting"
        self._update_cards()

        self._save_config()
        self._append_log("[gui] starting miner...")

        self.thread = MinerThread(cfg)
        self.thread.log_signal.connect(self._handle_worker_log)
        self.thread.status_signal.connect(self._handle_worker_status)
        self.thread.finished_signal.connect(self._handle_worker_finished)
        self.thread.start()

        self.backend_card.set_value(cfg.normalized_scan_backend())
        self.side_scanner_value.setText(cfg.normalized_scan_backend())
        self.right_tabs.setCurrentIndex(0)
        self._sync_button_state(running=True)

    def _stop_miner(self) -> None:
        if self.thread is None:
            return
        self._append_log("[gui] stop requested")
        self.thread.request_stop()
        self._sync_button_state(running=False)

    def _handle_worker_finished(self) -> None:
        self._append_log("[gui] worker stopped")
        self.current_status = "stopped"
        self._update_cards()
        self._sync_button_state(running=False)

        if self.thread is not None:
            self.thread.quit()
            self.thread.wait(1000)
            self.thread = None

    def _sync_button_state(self, running: bool) -> None:
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)

    def _handle_worker_status(self, status: str) -> None:
        self.current_status = status
        self._update_cards()
        self._append_log(f"[status] {status}")

    def _handle_worker_log(self, line: str) -> None:
        self._parse_log_for_cards(line)
        self._append_log(line)

    def _append_log(self, line: str) -> None:
        self.log_lines.append(line)
        self._append_to_visible_log(line)

    def _append_to_visible_log(self, line: str) -> None:
        text_filter = self.log_filter_edit.text().strip().lower()
        if text_filter and text_filter not in line.lower():
            return

        self.log_edit.appendPlainText(line)

        if self.autoscroll_check.isChecked():
            cursor = self.log_edit.textCursor()
            cursor.movePosition(QTextCursor.End)
            self.log_edit.setTextCursor(cursor)

    def _rebuild_log_view(self) -> None:
        filt = self.log_filter_edit.text().strip().lower()
        self.log_edit.clear()

        for line in self.log_lines:
            if not filt or filt in line.lower():
                self.log_edit.appendPlainText(line)

        if self.autoscroll_check.isChecked():
            cursor = self.log_edit.textCursor()
            cursor.movePosition(QTextCursor.End)
            self.log_edit.setTextCursor(cursor)

    def _clear_log(self) -> None:
        self.log_lines.clear()
        self.log_edit.clear()

    def _save_log(self) -> None:
        default_path = os.path.join(_logs_dir(), "bitcoin_miner_log.txt")
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Log",
            default_path,
            "Text Files (*.txt);;All Files (*)",
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(self.log_lines))
            self._append_log(f"[gui] log saved to {path}")
        except Exception as exc:
            QMessageBox.critical(self, "Save Log Failed", str(exc))

    def _parse_log_for_cards(self, line: str) -> None:
        if "[worker] scanner=" in line:
            scanner_name = line.split("scanner=", 1)[1].strip()
            self.backend_card.set_value(scanner_name)
            self.side_scanner_value.setText(scanner_name)

        m_job = re.search(r"\[worker\] new_job job_id=([^\s]+)", line)
        if m_job:
            self.last_job_id = m_job.group(1)

        m_nonce = re.search(r"nonce=([0-9a-fA-F]{8})", line)
        if m_nonce:
            self.last_nonce = m_nonce.group(1)

        if "[submit] accepted" in line:
            self.accepted_count += 1

        if "[submit] rejected" in line:
            self.rejected_count += 1

        self._update_cards()

    def _update_cards(self) -> None:
        self.status_card.set_value(self.current_status)
        self.job_card.set_value(self.last_job_id)
        self.accepted_card.set_value(str(self.accepted_count))
        self.rejected_card.set_value(str(self.rejected_count))
        self.nonce_card.set_value(self.last_nonce)

        self.side_status_value.setText(self.current_status)
        self.header_status_label.setText(self.current_status.upper())

    def _browse_native_dll(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select BitcoinProject DLL",
            self.native_dll_edit.text().strip() or str(_exe_dir()),
            "DLL Files (*.dll);;All Files (*)",
        )
        if path:
            self.native_dll_edit.setText(path)

    def _browse_kernel(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select OpenCL Kernel",
            self.kernel_path_edit.text().strip() or str(_exe_dir()),
            "OpenCL Files (*.cl);;All Files (*)",
        )
        if path:
            self.kernel_path_edit.setText(path)

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.thread is not None and self.thread.isRunning():
            self.thread.request_stop()
            self.thread.wait(3000)
        event.accept()


def run() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("Bitcoin Miner Control Panel")
    app.setStyle("Fusion")

    font = app.font()
    font.setPointSize(10)
    app.setFont(font)

    window = BitcoinMinerWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    run()