"""

"""

from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtCore import Qt
from binaryninja import *
from defunct.widgets import BinjaWidget
import defunct.widgets
import epdb
import operator

class StatisticsWidget(BinjaWidget):
    """Binja Statistics plugin
        Basic binary statistics.
    """
    def __init__(self):

        super(StatisticsWidget, self).__init__('Xrefs')
        self._table = QtWidgets.QTableWidget()
        self._table.setColumnCount(2)
        self._table.setHorizontalHeaderLabels(['Function', 'xrefs'])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.verticalHeader().setVisible(False)
        self.setLayout(QtWidgets.QStackedLayout())
        self.layout().addWidget(self._table)
        self.setObjectName('BNPlugin_Statistics')

    @QtCore.pyqtSlot(list)
    def xrefs(self, bv):
        """ Scans a binary view function xrefs 
        :param bv:  The BinaryView to use
        :type bv: binaryninja.BinaryView
        :return:
        """
        self._view = bv
        self._table.setRowCount(len(bv.functions))

	stat = {}
	for f in bv.functions:
		stat[f.name] = len(bv.get_code_refs(f.start))

	sort = sorted(stat.items(), key=operator.itemgetter(1))
	sort.reverse()

	i = 0
        for it in sort:
            name = QtWidgets.QTableWidgetItem(it[0])
            name.setFlags(Qt.ItemIsEnabled)
            xrefs = QtWidgets.QTableWidgetItem('%d' % it[1])
            xrefs.setFlags(Qt.ItemIsEnabled)
            xrefs.setForeground(QtGui.QColor(162, 217, 175))
            self._table.setItem(i, 1, xrefs)
            self._table.setItem(i, 0, name)
	    i = i+1

        self._table.cellDoubleClicked.connect(self.cell_action)
        self._thread.terminate()
        self._core.show()
        self._core.selectTab(self)
        self.show()

    def cell_action(self, row, column):
        # TODO: view highlighting
        self.navigate(self._view, self._table.item(row, 0).text())

    def navigate(self, bv, name):
        bv.navigate('Graph:' + bv.view_type, bv.get_symbol_by_raw_name(name).address)



d = StatisticsWidget()
def xrefs(bv):
    d.xrefs(bv)

PluginCommand.register('Function xrefs', 'Show number of xrefs for each function', xrefs)
