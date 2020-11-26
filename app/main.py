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
#  main.py

import falcon
from dogpile.cache import make_region
from scalecodec.updater import update_type_registries

from app.middleware import CatchAllMiddleware
from app.middleware.context import ContextMiddleware
from app.settings import DOGPILE_CACHE_SETTINGS
from app.resources import jsonrpc

# Gracefully update type registries in Scale codec
try:
    update_type_registries()
except Exception:
    pass

# Define cache region
cache_region = make_region().configure(
    'dogpile.cache.redis',
    arguments={
        'host': DOGPILE_CACHE_SETTINGS['host'],
        'port': DOGPILE_CACHE_SETTINGS['port'],
        'db': DOGPILE_CACHE_SETTINGS['db'],
        'distributed_lock': True
    }
)

# Define application
app = falcon.API(middleware=[
    CatchAllMiddleware(catch_all_route='/'),
    ContextMiddleware()
])

# Application routes
app.add_route('/', jsonrpc.JSONRPCResource(cache_region))
