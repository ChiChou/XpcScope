from datetime import datetime
from queue import Queue
import platform
import re


from PySide6.QtWidgets import QHBoxLayout, QWidget, QTreeView, QSplitter, QTextEdit, QTreeWidget, QTreeWidgetItem
from PySide6.QtCore import Qt, QItemSelection
from PySide6.QtGui import QStandardItemModel, QStandardItem, QFont

from xpcscope.hexdump import hexdump


def monospace():
    system = platform.system()
    mapping = {
        'Windows': 'Consolas',
        'Darwin': 'Monaco',
        'Linux': 'DejaVu Sans Mono'
    }

    return mapping.get(system, 'monospace')


class ListView(QWidget):
    _tree: QTreeView

    def __init__(self, parent=None):
        super(ListView, self).__init__(parent)
        self.setObjectName("ListView")

        self._counter = 0
        self._data: list[tuple[dict, bytes]] = []

        splitter = QSplitter()
        splitter.setOrientation(Qt.Orientation.Vertical)

        self._model = model = QStandardItemModel()
        model.setHorizontalHeaderLabels(
            ['#', 'Time', 'Direction', 'pid', 'Service', 'Message'])

        tree = QTreeView()
        tree.setUniformRowHeights(True)
        tree.setSelectionBehavior(QTreeView.SelectionBehavior.SelectRows)
        tree.setModel(model)
        tree.selectionModel().selectionChanged.connect(self._on_select_message)

        detail = MessageDetail()

        splitter.addWidget(tree)
        splitter.addWidget(detail)
        splitter.setSizes([200, 100])

        self._tree = tree
        self._detail = detail

        layout = QHBoxLayout()
        layout.addWidget(splitter)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)

        self._last_update = datetime.now()
        self._buffer = Queue()

    def _on_select_message(self, selected: QItemSelection, deselected: QItemSelection):
        if selected.count() < 1:
            return

        index = selected.indexes().pop().row()
        payload, data = self._data[index]

        self._detail.display_message(payload, data)

    def append_message(self, payload: dict, data: bytes):
        if payload.get('event') not in ('received', 'sent'):
            return

        self._counter += 1
        self._data.append((payload, data))

        desc: str = payload['message']['description']
        row = [
            QStandardItem(str(self._counter)),
            QStandardItem(datetime.now().strftime('%H:%M:%S.%f')),
            QStandardItem(payload['direction']),
            QStandardItem(str(payload.get('peer'))),
            QStandardItem(payload.get('name', 'N/A')),
            QStandardItem(re.sub(r'\n(\s*)', '', desc))
        ]
        for item in row:
            item.setEditable(False)

        self._model.appendRow(row)


class MessageDetail(QWidget):
    def __init__(self, parent=None):
        super(MessageDetail, self).__init__(parent)
        self.setObjectName("MessageDetail")

        splitter = QSplitter()
        splitter.setOrientation(Qt.Orientation.Horizontal)

        model = QStandardItemModel()
        tree = QTreeView()
        tree.setHeaderHidden(True)
        tree.setFont(QFont(monospace(), 12))
        tree.setModel(model)
        tree.selectionModel().selectionChanged.connect(self._on_select_node)

        text = QTextEdit("")
        text.setReadOnly(True)
        text.setFont(QFont(monospace(), 12))
        text.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)

        splitter.addWidget(tree)
        splitter.addWidget(text)

        self._text = text
        self._tree = tree
        self._model = model

        layout = QHBoxLayout()
        layout.addWidget(splitter)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)

        self._data = b''

    def _on_select_node(self, selected: QItemSelection, deselected: QItemSelection):
        if selected.count() < 1:
            return

        self._text.clear()
        index = selected.indexes().pop()
        node: QStandardItem = self._model.itemFromIndex(index)
        if node is None:
            return

        data = self._data
        payload = node.data(Qt.ItemDataRole.UserRole)

        if not payload:
            return

        try:
            if payload['type'] == 'data':
                text = str(hexdump(data))
            else:
                text = payload.get('value')

            self._text.setText(str(text))
        except TypeError:
            print('error', payload)

    def display_message(self, payload: dict, data: bytes):
        self._data = data

        model = self._model
        model.clear()

        message = payload['message']
        self._text.setPlainText(message['description'])

        def visit(item: dict, parent: QStandardItem):
            t = item.get('type')

            if t == 'nsxpc':
                args: list[str] = item['args']
                sel: str = item['sel']

                if len(args) == 0:
                    node = QStandardItem(sel)
                    node.setData(sel, Qt.ItemDataRole.UserRole)
                    parent.appendRow(node)
                    return

                else:
                    index = left = right = 0
                    for arg in args:
                        right = sel.find(':', left)
                        word = sel[left:right + 1]
                        node = QStandardItem(word)
                        node.setData(word, Qt.ItemDataRole.UserRole)
                        parent.appendRow(node)

                        child = QStandardItem(arg)
                        child.setData(arg, Qt.ItemDataRole.UserRole)
                        node.appendRow(child)

                        left = right + 1

                return

            short, *_ = item['description'].split('\n', 1)
            node = QStandardItem(short)
            node.setData(item, Qt.ItemDataRole.UserRole)

            if t == 'dictionary':
                keys = item['keys']
                values = item['values']

                for index, key in enumerate(keys):
                    value = values[index]
                    next_level = QStandardItem('"%s" =>' % key)
                    next_level.setData(value, Qt.ItemDataRole.UserRole)
                    node.appendRow(next_level)
                    visit(value, next_level)

            elif t == 'array':
                values = item['values']

                for value in values:
                    visit(value, node)

            parent.appendRow(node)

        root = model.invisibleRootItem()
        root.setEditable(False)
        root.setData(message, Qt.ItemDataRole.UserRole)
        visit(message, root)

        self._tree.expandAll()

    def dismiss_message(self):
        self._text.clear()
