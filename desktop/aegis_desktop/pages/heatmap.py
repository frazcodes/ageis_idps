from PySide6.QtWidgets import QWidget, QGridLayout, QLabel
from PySide6.QtGui import QColor, QPalette

class HeatMapWidget(QWidget):
    """Simple heat‑map visualization for a /24 subnet.
    Each cell represents an IP address; background colour encodes status:
    - Green  : online
    - Gray   : offline / unknown
    - Red    : flagged as suspicious (e.g., ARP spoofing)
    """

    def __init__(self, subnet_base: str = "192.168.1", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.subnet_base = subnet_base  # e.g., "192.168.1" for 192.168.1.0/24
        self._grid = QGridLayout(self)
        self._grid.setSpacing(2)
        self._cells: dict[int, QLabel] = {}
        self._build_grid()

    def _build_grid(self) -> None:
        for i in range(256):
            row = i // 16
            col = i % 16
            label = QLabel(f"{self.subnet_base}.{i}")
            label.setFixedSize(80, 20)
            label.setStyleSheet("background:#222831; color:#CBD5E1; border-radius:3px; font-size:10px; text-align:center;")
            self._grid.addWidget(label, row, col)
            self._cells[i] = label

    def update_status(self, online_ips: set[int], suspicious_ips: set[int] | None = None) -> None:
        """Refresh cell colours based on recent scan results.
        *online_ips* – set of host numbers that responded.
        *suspicious_ips* – optional set of host numbers flagged.
        """
        suspicious_ips = suspicious_ips or set()
        for i, label in self._cells.items():
            if i in suspicious_ips:
                colour = "#EF4444"  # crimson
            elif i in online_ips:
                colour = "#10B981"  # emerald
            else:
                colour = "#374151"  # dark‑gray
            label.setStyleSheet(f"background:{colour}; color:#FFFFFF; border-radius:3px; font-size:10px; text-align:center;")
