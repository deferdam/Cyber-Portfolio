"""Desktop app entry point. Run with `python -m desktop.main` (from src/) or `python
launch.py app`. Requires PySide6 (pip install -r requirements-desktop.txt)."""
import sys


def main() -> int:
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        sys.stderr.write(
            "PySide6 is not installed. Install the desktop extras:\n"
            "  pip install -r requirements-desktop.txt\n")
        return 1
    from desktop.window import MainWindow
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
