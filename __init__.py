"""
Benedikt Schmotzle <code<at>schmotzle.info> - 2016
    STARK - v0.0.1
        STARK is a Binary Ninja plugin loosly based on the JARVIS IDA Pro plugin
	by Carlos Garcia Prado.
	It is also using code from BinjaDock by defunct as a basis.

MIT License
Copyright (c) <2017> <Benedikt Schmotzle>                                                                                         
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtCore import Qt
from binaryninja import *
from defunct.widgets import BinjaWidget
from functools import partial
import defunct.widgets
import epdb
import operator

ws32_ordinals = {
'1' : 'imp_accept',
'2' : 'imp_bind',
'3' : 'imp_closesocket',
'4' : 'imp_connect',
'5' : 'imp_getpeername',
'6' : 'imp_getsockname',
'7' : 'imp_getsockopt',
'8' : 'imp_htonl',
'9' : 'imp_htons',
'10' : 'imp_ioctlsocket',
'11' : 'imp_inet_addr',
'12' : 'imp_inet_ntoa',
'13' : 'imp_listen',
'14' : 'imp_ntohl',
'15' : 'imp_ntohs',
'16' : 'imp_recv',
'17' : 'imp_recvfrom',
'18' : 'imp_select',
'19' : 'imp_send',
'20' : 'imp_sendto',
'21' : 'imp_setsockopt',
'22' : 'imp_shutdown',
'23' : 'imp_socket',
'24' : 'imp_GetAddrInfoW',
'25' : 'imp_GetNameInfoW',
'26' : 'imp_WSApSetPostRoutine',
'27' : 'imp_FreeAddrInfoW',
'28' : 'imp_WPUCompleteOverlappedRequest',
'29' : 'imp_WSAAccept',
'30' : 'imp_WSAAddressToStringA',
'31' : 'imp_WSAAddressToStringW',
'32' : 'imp_WSACloseEvent',
'33' : 'imp_WSAConnect',
'34' : 'imp_WSACreateEvent',
'35' : 'imp_WSADuplicateSocketA',
'36' : 'imp_WSADuplicateSocketW',
'37' : 'imp_WSAEnumNameSpaceProvidersA',
'38' : 'imp_WSAEnumNameSpaceProvidersW',
'39' : 'imp_WSAEnumNetworkEvents',
'40' : 'imp_WSAEnumProtocolsA',
'41' : 'imp_WSAEnumProtocolsW',
'42' : 'imp_WSAEventSelect',
'43' : 'imp_WSAGetOverlappedResult',
'44' : 'imp_WSAGetQOSByName',
'45' : 'imp_WSAGetServiceClassInfoA',
'46' : 'imp_WSAGetServiceClassInfoW',
'47' : 'imp_WSAGetServiceClassNameByClassIdA',
'48' : 'imp_WSAGetServiceClassNameByClassIdW',
'49' : 'imp_WSAHtonl',
'50' : 'imp_WSAHtons',
'51' : 'imp_gethostbyaddr',
'52' : 'imp_gethostbyname',
'53' : 'imp_getprotobyname',
'54' : 'imp_getprotobynumber',
'55' : 'imp_getservbyname',
'56' : 'imp_getservbyport',
'57' : 'imp_gethostname',
'58' : 'imp_WSAInstallServiceClassA',
'59' : 'imp_WSAInstallServiceClassW',
'60' : 'imp_WSAIoctl',
'61' : 'imp_WSAJoinLeaf',
'62' : 'imp_WSALookupServiceBeginA',
'63' : 'imp_WSALookupServiceBeginW',
'64' : 'imp_WSALookupServiceEnd',
'65' : 'imp_WSALookupServiceNextA',
'66' : 'imp_WSALookupServiceNextW',
'67' : 'imp_WSANSPIoctl',
'68' : 'imp_WSANtohl',
'69' : 'imp_WSANtohs',
'70' : 'imp_WSAProviderConfigChange',
'71' : 'imp_WSARecv',
'72' : 'imp_WSARecvDisconnect',
'73' : 'imp_WSARecvFrom',
'74' : 'imp_WSARemoveServiceClass',
'75' : 'imp_WSAResetEvent',
'76' : 'imp_WSASend',
'77' : 'imp_WSASendDisconnect',
'78' : 'imp_WSASendTo',
'79' : 'imp_WSASetEvent',
'80' : 'imp_WSASetServiceA',
'81' : 'imp_WSASetServiceW',
'82' : 'imp_WSASocketA',
'83' : 'imp_WSASocketW',
'84' : 'imp_WSAStringToAddressA',
'85' : 'imp_WSAStringToAddressW',
'86' : 'imp_WSAWaitForMultipleEvents',
'87' : 'imp_WSCDeinstallProvider',
'88' : 'imp_WSCEnableNSProvider',
'89' : 'imp_WSCEnumProtocols',
'90' : 'imp_WSCGetProviderPath',
'91' : 'imp_WSCInstallNameSpace',
'92' : 'imp_WSCInstallProvider',
'93' : 'imp_WSCUnInstallNameSpace',
'94' : 'imp_WSCUpdateProvider',
'95' : 'imp_WSCWriteNameSpaceOrder',
'96' : 'imp_WSCWriteProviderOrder',
'97' : 'imp_freeaddrinfo',
'98' : 'imp_getaddrinfo',
'99' : 'imp_getnameinfo',
'101' : 'imp_WSAAsyncSelect',
'102' : 'imp_WSAAsyncGetHostByAddr',
'103' : 'imp_WSAAsyncGetHostByName',
'104' : 'imp_WSAAsyncGetProtoByNumber',
'105' : 'imp_WSAAsyncGetProtoByName',
'106' : 'imp_WSAAsyncGetServByPort',
'107' : 'imp_WSAAsyncGetServByName',
'108' : 'imp_WSACancelAsyncRequest',
'109' : 'imp_WSASetBlockingHook',
'110' : 'imp_WSAUnhookBlockingHook',
'111' : 'imp_WSAGetLastError',
'112' : 'imp_WSASetLastError',
'113' : 'imp_WSACancelBlockingCall',
'114' : 'imp_WSAIsBlocking',
'115' : 'imp_WSAStartup',
'116' : 'imp_WSACleanup',
'151' : 'imp___WSAFDIsSet',
'500' : 'imp_WEP'
}

class StatisticsWidget(BinjaWidget):
    """Binja Statistics plugin
        Basic binary statistics.
    """
    def __init__(self, name, labels=[]):

        super(StatisticsWidget, self).__init__(name)
        self._table = QtWidgets.QTableWidget()
        self._table.setColumnCount(2)
        self._table.setHorizontalHeaderLabels(labels)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.verticalHeader().setVisible(False)
        self.setLayout(QtWidgets.QStackedLayout())
        self.layout().addWidget(self._table)
        self.setObjectName('BNPlugin_Statistics')

    @QtCore.pyqtSlot(list)
    def build_table(self, bv, get_data):
        """ Scans a binary view function xrefs 
        :param bv:  The BinaryView to use
        :type bv: binaryninja.BinaryView
        :return:
        """
        self._view = bv

	data = get_data(bv)
        self._table.setRowCount(len(data))

	i = 0
        for it in data:
            name = QtWidgets.QTableWidgetItem(it[0])
            name.setFlags(Qt.ItemIsEnabled)
	    if isInt(it[1]):
	            xrefs = QtWidgets.QTableWidgetItem(str(it[1]))
	    else:
	            xrefs = QtWidgets.QTableWidgetItem(it[1])
            xrefs.setFlags(Qt.ItemIsEnabled)
            xrefs.setForeground(QtGui.QColor(162, 217, 175))
            self._table.setItem(i, 1, xrefs)
            self._table.setItem(i, 0, name)
	    i = i+1

        self._table.cellDoubleClicked.connect(self.cell_action)
        self._core.show()
        self._core.selectTab(self)
        self.show()

    def cell_action(self, row, column):
        # TODO: view highlighting
        self.navigate(self._view, self._table.item(row, 0).text())

    def navigate(self, bv, name):
	try:
		address = bv.get_symbol_by_raw_name(name).address
	except:
		address = filter(lambda x: x.name == name, bv.functions)[0].start

        bv.navigate('Graph:' + bv.view_type, address)

def get_exts(bv):
	stat = {}
	for f in bv.functions:
		for bb in f.medium_level_il:
			for i in bb:
				if i.operation == MediumLevelILOperation.MLIL_CALL:
					try:
						bv.get_symbol_by_raw_name(f.name) # if it is has no symbol we don't count it
						if f.name in stat:
							stat[f.name] = stat[f.name] + 1
						else:
							stat[f.name] = 0
					except:
						continue

	sort = sorted(stat.items(), key=operator.itemgetter(1))
	sort.reverse()

	return sort


def get_bbs(bv):
	stat = {}
	for f in bv.functions:
		stat[f.name] = len(f.basic_blocks)

	sort = sorted(stat.items(), key=operator.itemgetter(1))
	sort.reverse()
	
	return sort

def get_xrefs(bv):
	stat = {}
	for f in bv.functions:
		stat[f.name] = len(bv.get_code_refs(f.start))

	sort = sorted(stat.items(), key=operator.itemgetter(1))
	sort.reverse()
	
	return sort

def get_calls(fun, bv):
	calls = [] 
	for bb in fun.medium_level_il:
		log_info(bb)
		for i in bb:
			log_info(i)
			if i.operation == MediumLevelILOperation.MLIL_CALL or i.operation == MediumLevelILOperation.MLIL_CALL_UNTYPED:
				log_info(i)
				if isinstance(i.dest.operands[0], MediumLevelILInstruction):
					address = i.dest.operands[0].operands[0]
				else:
					address = i.dest.operands[0]
				
				log_info(address)
				if not isinstance(address, long):
					# TODO: if register has known value test for that..
					continue

				name = bv.get_symbol_at(address)
				if not name:
					name = bv.get_function_at(address)
				log_info(name)

				calls.append([name.name, hex(address)])
				

	return calls

def get_strings(fun, bv):
	strings = [] 
	for bb in fun.medium_level_il:
		log_info(bb)
		for i in bb:
			log_info(i)
			try:
				i.operands
			except:
				continue
			for p in i.operands:
				log_info(p)
				if not isinstance(p, MediumLevelILInstruction):
					log_info(type(p))
					continue

				if p.operation == MediumLevelILOperation.MLIL_CONST and bv.get_segment_at(p.value.value):
					log_info("Found potential str")
					name = bv.read(p.value.value, 20).split("\x00")[0]
					strings.append([name, hex(p.value.value)])
#					filtered = filter(lambda x: x.start == p.value.value, bv.strings) 
#					if len(filtered) > 0:
#						strref = filtered[0]
##						name = bv.read(strref.start, strref.length)
#						strings.append([name, hex(p.value.value)])
#						log_info(name)

	return strings

def isInt(s):
    try: 
        int(s)
        return True
    except ValueError:
        return False

x = StatisticsWidget(name='Xrefs', labels=['Function', 'xrefs'])
b = StatisticsWidget(name='BBs', labels=['Function', 'bb'])
c = StatisticsWidget(name='Calls', labels=['Function', 'address'])
e = StatisticsWidget(name='External', labels=['Function', 'calls'])
s = StatisticsWidget(name='Strings', labels=['String', 'address'])


def xrefs(bv):
    x.build_table(bv, get_xrefs)

def bbs(bv):
    b.build_table(bv, get_bbs)

def exts(bv):
    e.build_table(bv, get_exts)

def calls(bv, fun):
    c.build_table(bv, partial(get_calls, fun))

def strings(bv, fun):
    s.build_table(bv, partial(get_strings, fun))

def ws2(bv, fun):

    for bb in fun.medium_level_il:
	for i in bb:
		if i.operation == MediumLevelILOperation.MLIL_CALL or i.operation == MediumLevelILOperation.MLIL_CALL_UNTYPED:
			log_info(i)
			if isinstance(i.dest.operands[0], MediumLevelILInstruction):
				address = i.dest.operands[0].operands[0]
			else:
				address = i.dest.operands[0]
			
			log_info(address)
			if not isinstance(address, long):
				# TODO: if register has known value test for that..
				continue

			sym = bv.get_symbol_at(address)

			if sym is not None:
				if "WS2_32" in sym.name:
					fun.set_comment(i.address, ws32_ordinals[sym.name.split("@")[0].split("_")[-1]])
			#    saved_name = sym.name
		        #    if sym.auto == True:
                #		bv.undefine_auto_symbol(sym)
		 #           else:
		  #              bv.undefine_user_symbol(sym)
	                
                   #         sym = types.Symbol(SymbolType.FunctionSymbol, address, saved_name+"LOL")
		    #        bv.define_user_symbol(sym)		
		#	    log_info(sym)


PluginCommand.register('Function xrefs', 'Show number of xrefs for each function', xrefs)
PluginCommand.register('Function bb', 'Show number of basic blocks for each function', bbs)
PluginCommand.register('Function external', 'Show number of calls to imported functions for each function', exts)
PluginCommand.register_for_function('Function calls', 'Show all calls out of the given function', calls)
PluginCommand.register_for_function('Function strings', 'Show all referenced strings of the given function', strings)
PluginCommand.register_for_function('Function ws2', 'Rename all ws2 calls in the function', ws2)
