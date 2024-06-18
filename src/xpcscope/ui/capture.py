import asyncio

import frida

from PySide6.QtWidgets import QErrorMessage, QMainWindow, QProgressDialog
from PySide6.QtCore import QSettings, QSize, Qt, Signal, QObject
from PySide6.QtGui import QIcon

import xpcscope.res

from xpcscope.core import load_script
from xpcscope.ui.listview import ListView


class AppendItemSignal(QObject):
    signal = Signal(dict, bytes)

    def __init__(self, parent=None):
        super().__init__(parent)

    def append(self, payload: dict, data: bytes):
        self.signal.emit(payload, data)


class CaptureWindow(QMainWindow):
    _session: frida.core.Session | None

    def __init__(self):
        super().__init__()

        self.setWindowTitle("XPCScope")

        self.settings = QSettings("XPCScope", "XPCScope")
        self.restoreGeometry(self.settings.value("geometry"))  # type: ignore
        self.restoreState(self.settings.value("state"))  # type: ignore

        self.setMinimumWidth(800)
        self.setMinimumHeight(600)

        self._session = None
        self._pid = 0
        self._list = ListView()
        self.setCentralWidget(self._list)

        self._create_menu()
        self._create_toolbar()

        self._progress_dialog = QProgressDialog(self)
        self._progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
        self._progress_dialog.setCancelButton(None)  # type: ignore

        self._append_signal = AppendItemSignal()
        self._append_signal.signal.connect(self._list.append_message)

    def loading(self, msg: str):
        class LoadingMessage:
            def __init__(self, dialog: QProgressDialog, message: str):
                self.dialog = dialog
                self.dialog.setLabelText(message)

            def __enter__(self):
                if not self.dialog.isVisible():
                    self.dialog.show()
                return self.dialog

            def __exit__(self, exc_type, exc_value, traceback):
                self.dialog.close()

        return LoadingMessage(self._progress_dialog, msg)

    async def attach(self, session: frida.core.Session):
        with self.loading("Initializing hook..."):
            self._session = session
            self._script = await asyncio.get_event_loop().run_in_executor(None, load_script, session, self._on_message)
            await self._script.exports_async.start()

            name, pid = await self._script.exports_async.name_and_pid()
            self._pid = pid

        self.setWindowTitle(f"XPCScope - {name}({pid})")

    async def detach(self):
        with self.loading("Stopping capture..."):
            if not self._session:
                return

            if not self._script.is_destroyed:
                await self._script.exports_async.stop()
            await asyncio.get_event_loop().run_in_executor(None, self._session.detach)

            self._session = None

        self.close()

    def _on_message(self, message: dict, data: bytes):
        payload = message.get('payload')
        if message.get('type') != 'send' or payload is None:
            return

        if payload.get('type') == 'error':
            QErrorMessage().showMessage(payload.get('message'))
            return

        self._append_signal.append(payload, data)

    def _create_toolbar(self):
        bar = self.addToolBar("Capture")
        bar.setObjectName('Capture')
        bar.setFloatable(False)
        bar.setMovable(False)
        bar.setIconSize(QSize(24, 24))
        # bar.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)

        bar.addSeparator()

        exit_action = bar.addAction("Exit")
        exit_action.setIcon(QIcon(':exit'))
        exit_action.triggered.connect(self.close)

    def _create_menu(self):
        self._menu = menu = self.menuBar()
        file_menu = menu.addMenu("&File")
        # file_menu.addAction("&Open")
        # file_menu.addAction("&Export...")
        # file_menu.addSeparator()
        file_menu.addAction("Exit")

        # edit_menu = menu.addMenu("&Edit")
        # edit_menu.addAction("Copy")

        help_menu = menu.addMenu("&Help")
        help_menu.addAction("About")
        # help_menu.addAction("Help")

    def closeEvent(self, event):
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("state", self.saveState())

        if self._session:
            event.ignore()
            asyncio.ensure_future(self.detach())
        else:
            super().closeEvent(event)
