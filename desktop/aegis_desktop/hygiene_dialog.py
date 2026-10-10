"""System Hygiene & Storage Optimization dialog.

Interactive modal dialog allowing analysts to inspect temporary file buildup,
malware staging caches, and trigger safe background purges with real-time feedback.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from aegis_desktop.services.system_cleaner import (
    HygieneCategory,
    HygieneCleanResult,
    HygieneScanResult,
    clean_system_hygiene,
    scan_system_hygiene,
)


class SystemHygieneDialog(QDialog):
    """Modal dialog for scanning and cleaning system temp & dropper folders."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Aegis IDPS — System Hygiene & Storage Optimization")
        self.setMinimumSize(680, 520)
        self.resize(720, 540)
        self.setStyleSheet("""
            QDialog {
                background-color: #0F172A;
                color: #F8FAFC;
                font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            }
            QFrame#StatCard {
                background-color: #1E293B;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 12px;
            }
            QFrame#CategoryRow {
                background-color: #1E293B;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 10px 14px;
            }
            QFrame#CategoryRow:hover {
                border-color: #475569;
                background-color: #243048;
            }
            QProgressBar {
                background-color: #1E293B;
                border: 1px solid #334155;
                border-radius: 4px;
                text-align: center;
                color: #F8FAFC;
                font-size: 11px;
                font-weight: 600;
            }
            QProgressBar::chunk {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #06B6D4,
                    stop:1 #10B981
                );
                border-radius: 3px;
            }
            QPushButton#PrimaryActionBtn {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0284C7,
                    stop:1 #0D9488
                );
                border: 1px solid #38BDF8;
                border-radius: 6px;
                color: #FFFFFF;
                font-size: 12px;
                font-weight: 700;
                padding: 8px 18px;
            }
            QPushButton#PrimaryActionBtn:hover {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0369A1,
                    stop:1 #0F766E
                );
                border-color: #7DD3FC;
            }
            QPushButton#PrimaryActionBtn:disabled {
                background: #334155;
                border-color: #475569;
                color: #94A3B8;
            }
            QPushButton#SecondaryActionBtn {
                background: #1E293B;
                border: 1px solid #475569;
                border-radius: 6px;
                color: #E2E8F0;
                font-size: 12px;
                font-weight: 600;
                padding: 8px 16px;
            }
            QPushButton#SecondaryActionBtn:hover {
                background: #334155;
                border-color: #64748B;
            }
        """)

        self._scan_result: HygieneScanResult | None = None
        self._category_checkboxes: dict[str, QCheckBox] = {}
        self._category_labels: dict[str, QLabel] = {}

        self._build_ui()
        self.refresh_scan()

    def _build_ui(self) -> None:
        root_lay = QVBoxLayout(self)
        root_lay.setContentsMargins(24, 20, 24, 20)
        root_lay.setSpacing(16)

        # 1. Header
        header = QHBoxLayout()
        header.setSpacing(14)
        icon_lbl = QLabel("🧹")
        icon_lbl.setStyleSheet("font-size: 28px;")
        header.addWidget(icon_lbl)

        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        title_lbl = QLabel("System Hygiene & Storage Optimization")
        title_lbl.setStyleSheet("font-size: 16px; font-weight: 800; color: #F8FAFC;")
        sub_lbl = QLabel(
            "Safely purge staging folders, flush malware dropper caches, and reclaim storage."
        )
        sub_lbl.setStyleSheet("font-size: 12px; color: #94A3B8;")
        title_box.addWidget(title_lbl)
        title_box.addWidget(sub_lbl)
        header.addLayout(title_box)
        header.addStretch(1)
        root_lay.addLayout(header)

        # 2. KPI Cards
        cards_lay = QHBoxLayout()
        cards_lay.setSpacing(12)

        self._card_junk_val = QLabel("0 B")
        self._card_junk_val.setStyleSheet("font-size: 20px; font-weight: 800; color: #38BDF8;")
        card1 = self._create_stat_card("Total Cleanable Data", self._card_junk_val)

        self._card_files_val = QLabel("0 files")
        self._card_files_val.setStyleSheet("font-size: 20px; font-weight: 800; color: #F59E0B;")
        card2 = self._create_stat_card("Files Targeted", self._card_files_val)

        self._card_status_val = QLabel("Ready to Scan")
        self._card_status_val.setStyleSheet("font-size: 18px; font-weight: 800; color: #10B981;")
        card3 = self._create_stat_card("Hygiene Posture", self._card_status_val)

        cards_lay.addWidget(card1)
        cards_lay.addWidget(card2)
        cards_lay.addWidget(card3)
        root_lay.addLayout(cards_lay)

        # 3. Target Categories Section
        cat_header = QLabel("CLEANUP TARGETS & STAGING PATHS")
        cat_header.setStyleSheet(
            "font-size: 11px; font-weight: 800; color: #64748B; letter-spacing: 0.6px;"
        )
        root_lay.addWidget(cat_header)

        self._categories_container = QVBoxLayout()
        self._categories_container.setSpacing(8)
        root_lay.addLayout(self._categories_container)

        # 4. Progress bar (hidden unless running)
        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setFixedHeight(8)
        self._progress.setTextVisible(False)
        self._progress.setVisible(False)
        root_lay.addWidget(self._progress)

        # 5. Status / Feedback Banner
        self._status_banner = QLabel("Ready")
        self._status_banner.setStyleSheet(
            "color: #94A3B8; font-size: 11px; font-family: 'Consolas', monospace;"
        )
        root_lay.addWidget(self._status_banner)

        # 6. Action Button Bar
        btn_bar = QHBoxLayout()
        btn_bar.setSpacing(10)

        self._scan_btn = QPushButton("🔍  Scan System")
        self._scan_btn.setObjectName("SecondaryActionBtn")
        self._scan_btn.clicked.connect(self.refresh_scan)
        btn_bar.addWidget(self._scan_btn)

        btn_bar.addStretch(1)

        self._purge_btn = QPushButton("⚡  Purge & Optimize Now")
        self._purge_btn.setObjectName("PrimaryActionBtn")
        self._purge_btn.clicked.connect(self._on_purge_clicked)
        btn_bar.addWidget(self._purge_btn)

        close_btn = QPushButton("Close")
        close_btn.setObjectName("SecondaryActionBtn")
        close_btn.clicked.connect(self.accept)
        btn_bar.addWidget(close_btn)

        root_lay.addLayout(btn_bar)

    def _create_stat_card(self, title: str, val_label: QLabel) -> QFrame:
        card = QFrame()
        card.setObjectName("StatCard")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.setSpacing(4)
        t_lbl = QLabel(title.upper())
        t_lbl.setStyleSheet(
            "font-size: 10px; font-weight: 700; color: #64748B; letter-spacing: 0.5px;"
        )
        lay.addWidget(t_lbl)
        lay.addWidget(val_label)
        return card

    def refresh_scan(self) -> None:
        """Scan system targets and update UI metrics."""
        self._status_banner.setText("Scanning temporary staging paths...")
        self._scan_result = scan_system_hygiene()

        self._card_junk_val.setText(self._scan_result.total_bytes_formatted)
        self._card_files_val.setText(f"{self._scan_result.total_files:,} files")

        if self._scan_result.total_bytes > 500_000_000:
            self._card_status_val.setText("Needs Cleanup")
            self._card_status_val.setStyleSheet(
                "font-size: 18px; font-weight: 800; color: #F59E0B;"
            )
        elif self._scan_result.total_bytes > 0:
            self._card_status_val.setText("Moderate Buildup")
            self._card_status_val.setStyleSheet(
                "font-size: 18px; font-weight: 800; color: #38BDF8;"
            )
        else:
            self._card_status_val.setText("Sanitized")
            self._card_status_val.setStyleSheet(
                "font-size: 18px; font-weight: 800; color: #10B981;"
            )

        # Populate or update category rows
        self._update_category_rows(self._scan_result.categories)
        self._status_banner.setText(
            f"✓ Scan complete: {self._scan_result.total_files:,} files "
            f"({self._scan_result.total_bytes_formatted}) discovered."
        )

    def _update_category_rows(self, categories: tuple[HygieneCategory, ...]) -> None:
        # If already populated, just update labels
        if self._category_checkboxes:
            for cat in categories:
                lbl = self._category_labels.get(cat.id)
                if lbl:
                    lbl.setText(f"{cat.file_count:,} files  ·  {cat.size_formatted}")
            return

        # Initial populate
        for cat in categories:
            row = QFrame()
            row.setObjectName("CategoryRow")
            r_lay = QHBoxLayout(row)
            r_lay.setContentsMargins(12, 8, 12, 8)
            r_lay.setSpacing(12)

            cb = QCheckBox(cat.name)
            cb.setChecked(cat.accessible and cat.is_safe_to_purge)
            cb.setEnabled(cat.accessible)
            cb.setStyleSheet("font-weight: 700; color: #E2E8F0; font-size: 12px;")
            self._category_checkboxes[cat.id] = cb
            r_lay.addWidget(cb)

            path_lbl = QLabel(f"({cat.path})")
            path_lbl.setStyleSheet("color: #64748B; font-size: 11px;")
            r_lay.addWidget(path_lbl)

            r_lay.addStretch(1)

            val_lbl = QLabel(f"{cat.file_count:,} files  ·  {cat.size_formatted}")
            val_lbl.setStyleSheet(
                "color: #38BDF8; font-weight: 600; font-size: 12px; font-family: monospace;"
            )
            self._category_labels[cat.id] = val_lbl
            r_lay.addWidget(val_lbl)

            self._categories_container.addWidget(row)

    def _on_purge_clicked(self) -> None:
        """Confirm with analyst and execute safe purge."""
        selected_ids = [
            cat_id for cat_id, cb in self._category_checkboxes.items() if cb.isChecked()
        ]
        if not selected_ids:
            QMessageBox.information(
                self, "No Targets Selected", "Please select at least one cleanup target category."
            )
            return

        confirm = QMessageBox.question(
            self,
            "Confirm System Hygiene Purge",
            "Are you sure you want to purge selected temporary staging files?\n\n"
            "• Active files locked by Windows will be safely skipped.\n"
            "• Malware staging caches and temporary residue will be removed.\n"
            "• Reclaimed disk space is freed immediately.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        self._purge_btn.setEnabled(False)
        self._scan_btn.setEnabled(False)
        self._progress.setVisible(True)
        self._progress.setValue(35)
        self._status_banner.setText("Purging temporary and staging files safely...")

        result: HygieneCleanResult = clean_system_hygiene(selected_ids)

        self._progress.setValue(100)
        self._purge_btn.setEnabled(True)
        self._scan_btn.setEnabled(True)

        msg = (
            f"✓ Purge Complete: {result.cleaned_files:,} files deleted, "
            f"{result.reclaimed_bytes_formatted} disk space reclaimed. "
            f"({result.skipped_files} active locked files safely preserved)."
        )
        self._status_banner.setText(msg)

        # Trigger toast on parent window if available
        parent = self.parent()
        show_toast_fn: object = getattr(parent, "show_toast", None)
        if callable(show_toast_fn):
            toast_text = (
                f"Reclaimed {result.reclaimed_bytes_formatted} "
                f"({result.cleaned_files:,} files purged)"
            )
            show_toast_fn(
                "System Hygiene Optimized",
                toast_text,
                level="success",
            )

        # Rescan to reflect updated state and preserve purge summary
        self.refresh_scan()
        self._status_banner.setText(msg)


__all__ = ["SystemHygieneDialog"]
