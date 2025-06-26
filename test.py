import sys, os, hashlib, sqlite3
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton,
    QVBoxLayout, QLabel, QMessageBox, QFileDialog
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont, QColor, QPalette

# ✅ Buffered SHA-256 for better performance
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

# ✅ Background Scanner Thread
class ScanThread(QThread):
    finished = pyqtSignal(list)

    def __init__(self, root_dir):
        super().__init__()
        self.root_dir = root_dir

    def run(self):
        infected = []

        # ✅ All allowed extensions
        VALID_EXTS = [
            '.exe', '.dll', '.zip', '.bat', '.com', '.jar',
            '.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx'
        ]

        def is_malicious(h):
            try:
                conn = sqlite3.connect("signatures.db")
                cur = conn.cursor()
                cur.execute("SELECT malware_name, threat_level FROM signatures WHERE sha256_hash = ?", (h,))
                result = cur.fetchone()
                conn.close()
                return result
            except:
                return None

        for root, dirs, files in os.walk(self.root_dir):
            for file in files:
                path = os.path.join(root, file)

                # ✅ Check extension from full path
                if not any(path.lower().endswith(ext) for ext in VALID_EXTS):
                    continue

                try:
                    if os.path.getsize(path) > 50 * 1024 * 1024:
                        continue
                    h = sha256_file(path)
                    result = is_malicious(h)
                    if result:
                        infected.append((path, result[0], result[1]))
                except:
                    continue

        self.finished.emit(infected)

# ✅ Main UI App
class AntivirusApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Antivirus Scanner")
        self.resize(500, 250)

        # Style
        self.setFont(QFont("Segoe UI", 10))
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor("#f4f4f4"))
        self.setPalette(palette)

        # Heading
        self.heading = QLabel("🛡️ Simple Antivirus Scanner")
        self.heading.setFont(QFont("Segoe UI", 14, QFont.Bold))
        self.heading.setStyleSheet("color: #333; margin-bottom: 10px;")
        self.heading.setAlignment(Qt.AlignCenter)

        # Status Label
        self.label = QLabel("Click below to scan a folder")
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setStyleSheet("color: #555; padding: 5px;")

        # Scan Button
        self.button = QPushButton("🗂️ Scan Folder")
        self.button.setFixedHeight(40)
        self.button.setStyleSheet("""
            QPushButton {
                background-color: #0078d7;
                color: white;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #005ea6;
            }
        """)
        self.button.clicked.connect(self.start_scan)

        # Layout
        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(15)
        layout.addWidget(self.heading)
        layout.addWidget(self.label)
        layout.addWidget(self.button)
        self.setLayout(layout)

    def start_scan(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if not folder:
            return
        self.label.setText(f"🔄 Scanning: {folder}")
        self.thread = ScanThread(folder)
        self.thread.finished.connect(self.show_result)
        self.thread.start()

    def show_result(self, infected):
        if infected:
            msg = "\n".join([f"{p} → {n} ({l})" for p, n, l in infected])
            QMessageBox.information(self, "Malware Found", msg)
        else:
            QMessageBox.information(self, "Clean", "No malware found.")
        self.label.setText("✅ Scan Complete")

# ✅ Entry Point
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = AntivirusApp()
    win.show()
    sys.exit(app.exec_())
