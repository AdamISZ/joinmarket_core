from __future__ import print_function

import logging

#Full joinmarket uses its own bitcoin module;
#other implementations (like wallet plugins)
#can optionally include their own, which must
#be implemented as an interface in btc.py
from btc import *

from .support import get_log, calc_cj_fee, debug_dump_object, \
    choose_sweep_orders, choose_orders, \
    pick_order, cheapest_order_choose, weighted_order_choose, \
    rand_norm_array, rand_pow_array, rand_exp_array, joinmarket_alert, core_alert
from .jsonrpc import JsonRpcError, JsonRpcConnectionError, JsonRpc
from .old_mnemonic import mn_decode, mn_encode
from .slowaes import decryptData, encryptData
from .wallet import AbstractWallet, BitcoinCoreInterface, Wallet, \
    BitcoinCoreWallet, ElectrumWrapWallet
from .configure import load_program_config, jm_single, get_p2pk_vbyte, \
    get_network, jm_single, get_network, validate_address
from .blockchaininterface import BlockrInterface, BlockchainInterface
from .irc import random_nick, IRCMessageChannel
from .taker import Taker
# Set default logging handler to avoid "No handler found" warnings.

try:
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

logging.getLogger(__name__).addHandler(NullHandler())

