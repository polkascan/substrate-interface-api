#  Python Substrate API
#
#  Copyright 2018-2020 openAware BV (NL).
#  This file is part of Polkascan.
#
#  Polkascan is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  Polkascan is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with Polkascan. If not, see <http://www.gnu.org/licenses/>.
#
#  settings.py
import os

SUBSTRATE_RPC_URL = os.environ.get("SUBSTRATE_RPC_URL", "http://substrate-node:9933/")
SUBSTRATE_ADDRESS_TYPE = int(os.environ.get("SUBSTRATE_ADDRESS_TYPE", 42))

TYPE_REGISTRY = os.environ.get("TYPE_REGISTRY", "default")

DOGPILE_CACHE_SETTINGS = {
    'host': os.environ.get("DOGPILE_CACHE_HOST", "redis"),
    'port': os.environ.get("DOGPILE_CACHE_PORT", 6379),
    'db': os.environ.get("DOGPILE_CACHE_DB", 1)
}

DEBUG = False

try:
    from app.local_settings import *
except ImportError:
    pass
