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
#  jsonrpc.py

import falcon
from scalecodec.type_registry import load_type_registry_file

from scalecodec.exceptions import InvalidScaleTypeValueException, RemainingScaleBytesNotEmptyException

from app import settings
from scalecodec.base import RuntimeConfiguration
from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException

from app.resources.base import BaseResource


class JSONRPCResource(BaseResource):

    def __init__(self, cache_region):

        self.cache_region = cache_region

        # Check for custom types in Redis

        self.substrate = None

        custom_type_registry = self.cache_region.get('CUSTOM_TYPE_REGISTRY')
        self.init_type_registry(custom_type_registry)

        self.block_hash = None
        self.metadata_decoder = None
        self.runtime_version = None

        self.metadata_cache = {}

        self.methods = [
            'rpc_methods',
            'runtime_decodeScale',
            'runtime_encodeScale',
            'runtime_getMetadata',
            'runtime_getMetadataModules',
            'runtime_getMetadataCallFunctions',
            'runtime_getMetadataCallFunction',
            'runtime_getMetadataEvents',
            'runtime_getMetadataEvent',
            'runtime_getMetadataConstants',
            'runtime_getMetadataConstant',
            'runtime_getMetadataStorageFunctions',
            'runtime_getMetadataStorageFunction',
            'runtime_getMetadataErrors',
            'runtime_getMetadataError',
            'runtime_getState',
            'runtime_getTypeRegistry',
            'runtime_getType',
            'runtime_getCustomTypes',
            'runtime_addCustomType',
            'runtime_setCustomTypes',
            'runtime_removeCustomType',
            'runtime_resetCustomTypes',
            'runtime_getBlock',
            'runtime_createSignaturePayload',
            'runtime_createExternalSignerPayload',
            'runtime_createExtrinsic',
            'runtime_submitExtrinsic',
            'runtime_getPaymentInfo',
            'keypair_create',
            'keypair_inspect',
            'keypair_sign',
            'keypair_verify'
        ]

    def get_request_param(self, params):
        try:
            return params.pop(0)
        except IndexError:
            raise ValueError("Not enough parameters provided")

    def init_type_registry(self, custom_type_registry=None):

        if settings.TYPE_REGISTRY_FILE:
            type_registry = load_type_registry_file(settings.TYPE_REGISTRY_FILE)
        else:
            type_registry = {}

        if custom_type_registry:
            type_registry.update(custom_type_registry)

        self.substrate = SubstrateInterface(
            url=settings.SUBSTRATE_RPC_URL,
            address_type=settings.SUBSTRATE_ADDRESS_TYPE,
            type_registry_preset=settings.TYPE_REGISTRY,
            type_registry=custom_type_registry
        )

        if settings.DEBUG:
            print('Custom types at init: ', custom_type_registry)
            self.substrate.debug = True

    def init_request(self, params=None):

        if params:
            self.block_hash = self.get_request_param(params)
            if type(self.block_hash) is int:
                self.block_hash = self.substrate.get_block_hash(self.block_hash)

    def on_post(self, req, resp):
        self.block_hash = None
        self.metadata_decoder = None
        self.runtime_version = None

        self.substrate.request_id = req.media.get('id')

        method = req.media.get('method')
        params = req.media.get('params', [])

        # Check request requirements
        if not req.media.get('jsonrpc'):
            resp.media = {
                "error": {
                    "code": -32600,
                    "message": "Unsupported JSON-RPC protocol version"
                },
                "id": req.media.get('id')
            }
        elif not method:
            resp.media = {
                "error": {
                    "code": -32601,
                    "message": "Method not found"
                },
                "id": req.media.get('id')
            }
        elif method not in self.methods:
            # Default pass through request to Substrate RPC
            resp.media = self.substrate.rpc_request(method, params)
        else:
            resp.status = falcon.HTTP_200
            try:

                # Process methods
                if method == 'runtime_getBlock':
                    self.init_request(params)
                    response = {
                        "jsonrpc": "2.0",
                        "result": self.substrate.get_runtime_block(block_hash=self.block_hash),
                        "id": req.media.get('id')
                    }
                elif method == 'runtime_getState':
                    # Init params
                    storage_params = None

                    # Process params
                    module = self.get_request_param(params)
                    storage_function = self.get_request_param(params)
                    if params:
                        storage_params = self.get_request_param(params)

                    self.init_request(params)

                    # Get response
                    response = self.substrate.get_runtime_state(
                        module=module,
                        storage_function=storage_function,
                        params=storage_params,
                        block_hash=self.block_hash
                    )

                elif method == 'runtime_getMetadata':
                    # Process params
                    self.init_request(params)

                    # Get response
                    response = self.substrate.get_runtime_metadata(block_hash=self.block_hash)

                elif method in ['runtime_createSignaturePayload', 'runtime_createExternalSignerPayload']:
                    account = self.get_request_param(params)
                    call_module = self.get_request_param(params)
                    call_function = self.get_request_param(params)
                    call_params = self.get_request_param(params)
                    tip = self.get_request_param(params) or 0
                    era = self.get_request_param(params)

                    self.init_request(params)

                    try:
                        # Create call
                        call = self.substrate.compose_call(
                            call_module=call_module,
                            call_function=call_function,
                            call_params=call_params,
                            block_hash=self.block_hash
                        )

                        nonce = self.substrate.get_account_nonce(account) or 0

                        if isinstance(era, dict) and 'current' not in era and 'phase' not in era:
                            # Retrieve current block id
                            era['current'] = self.substrate.get_block_number(self.substrate.get_chain_head())

                        if method == 'runtime_createExternalSignerPayload':
                            include_call_length = True
                        else:
                            include_call_length = False

                        # Generate signature payload
                        signature_payload = self.substrate.generate_signature_payload(
                            call=call,
                            nonce=nonce,
                            tip=tip,
                            era=era,
                            include_call_length=include_call_length
                        )

                        response = {
                            "jsonrpc": "2.0",
                            "result": {
                                'signature_payload': str(signature_payload),
                                'nonce': nonce,
                                'era': era
                            },
                            "id": req.media.get('id')
                        }
                    except ValueError as e:
                        response = {
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -999,
                                "message": str(e)
                            },
                            "id": req.media.get('id')
                        }
                elif method in ['runtime_submitExtrinsic', 'runtime_createExtrinsic']:
                    account = self.get_request_param(params)
                    call_module = self.get_request_param(params)
                    call_function = self.get_request_param(params)
                    call_params = self.get_request_param(params)
                    tip = self.get_request_param(params) or 0
                    era = self.get_request_param(params)
                    crypto_type = int(self.get_request_param(params) or 1)
                    signature = self.get_request_param(params)

                    self.init_request(params)

                    try:
                        # Create call
                        call = self.substrate.compose_call(
                            call_module=call_module,
                            call_function=call_function,
                            call_params=call_params,
                            block_hash=self.block_hash
                        )

                        nonce = self.substrate.get_account_nonce(account) or 0

                        # Create keypair with only public given given in request
                        keypair = Keypair(ss58_address=account, crypto_type=crypto_type)

                        if isinstance(era, dict) and 'current' in era:
                            era['current'] = int(era['current'])

                        # Create extrinsic
                        extrinsic = self.substrate.create_signed_extrinsic(
                            call=call,
                            keypair=keypair,
                            nonce=nonce,
                            signature=signature,
                            tip=tip,
                            era=era
                        )

                        if method == 'runtime_createExtrinsic':
                            result = str(extrinsic.data)
                        else:
                            # Submit extrinsic to the node
                            result = self.substrate.submit_extrinsic(
                                extrinsic=extrinsic
                            )

                        response = {
                            "jsonrpc": "2.0",
                            "result": {
                                "extrinsic_hash": result.extrinsic_hash,
                                "block_hash": result.block_hash,
                                "finalized": result.finalized,
                            },
                            "id": req.media.get('id')
                        }
                    except ValueError as e:
                        response = {
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -999,
                                "message": str(e)
                            },
                            "id": req.media.get('id')
                        }
                    except SubstrateRequestException as e:
                        response = {
                            "jsonrpc": "2.0",
                            "error": e.args[0],
                            "id": req.media.get('id')
                        }
                elif method == 'runtime_getPaymentInfo':

                    account = self.get_request_param(params)
                    call_module = self.get_request_param(params)
                    call_function = self.get_request_param(params)
                    call_params = self.get_request_param(params)

                    # Create call
                    call = self.substrate.compose_call(
                        call_module=call_module,
                        call_function=call_function,
                        call_params=call_params
                    )

                    # Create keypair with only public given given in request
                    keypair = Keypair(ss58_address=account)

                    response = {
                        "jsonrpc": "2.0",
                        "result": self.substrate.get_payment_info(call=call, keypair=keypair),
                        "id": req.media.get('id')
                    }

                elif method == 'runtime_getMetadataModules':

                    self.init_request(params)

                    response = {
                        "jsonrpc": "2.0",
                        "result": self.substrate.get_metadata_modules(block_hash=self.block_hash),
                        "id": req.media.get('id')
                    }
                elif method == 'runtime_getMetadataCallFunctions':

                    self.init_request(params)

                    call_list = self.substrate.get_metadata_call_functions(block_hash=self.block_hash)

                    response = {
                        "jsonrpc": "2.0",
                        "result": call_list,
                        "id": req.media.get('id')
                    }

                elif method == 'runtime_getMetadataCallFunction':

                    param_call_module = self.get_request_param(params)
                    param_call_module_function = self.get_request_param(params)

                    self.init_request(params)

                    result = self.substrate.get_metadata_call_function(
                        module_name=param_call_module,
                        call_function_name=param_call_module_function,
                        block_hash=self.block_hash
                    )

                    response = {
                        "jsonrpc": "2.0",
                        "result": result,
                        "id": req.media.get('id')
                    }
                elif method == 'runtime_getMetadataEvents':

                    self.init_request(params)

                    event_list = self.substrate.get_metadata_events(block_hash=self.block_hash)

                    response = {
                        "jsonrpc": "2.0",
                        "result": event_list,
                        "id": req.media.get('id')
                    }

                elif method == 'runtime_getMetadataEvent':

                    param_call_module = self.get_request_param(params)
                    param_call_module_event = self.get_request_param(params)

                    self.init_request(params)

                    result = self.substrate.get_metadata_event(
                        module_name=param_call_module,
                        event_name=param_call_module_event,
                        block_hash=self.block_hash
                    )

                    response = {
                        "jsonrpc": "2.0",
                        "result": result,
                        "id": req.media.get('id')
                    }
                elif method == 'runtime_getMetadataConstants':

                    self.init_request(params)

                    constant_list = self.substrate.get_metadata_constants(block_hash=self.block_hash)

                    response = {
                        "jsonrpc": "2.0",
                        "result": constant_list,
                        "id": req.media.get('id')
                    }
                elif method == 'runtime_getMetadataConstant':

                    module_name = self.get_request_param(params)
                    constant_name = self.get_request_param(params)

                    self.init_request(params)

                    result = self.substrate.get_metadata_constant(
                        module_name=module_name,
                        constant_name=constant_name,
                        block_hash=self.block_hash
                    )

                    response = {
                        "jsonrpc": "2.0",
                        "result": result,
                        "id": req.media.get('id')
                    }
                elif method == 'runtime_getMetadataStorageFunctions':
                    self.init_request(params)

                    storage_list = self.substrate.get_metadata_storage_functions(block_hash=self.block_hash)

                    response = {
                        "jsonrpc": "2.0",
                        "result": storage_list,
                        "id": req.media.get('id')
                    }
                elif method == 'runtime_getMetadataStorageFunction':

                    module_name = self.get_request_param(params)
                    storage_name = self.get_request_param(params)

                    self.init_request(params)

                    result = self.substrate.get_metadata_storage_function(
                        module_name=module_name,
                        storage_name=storage_name,
                        block_hash=self.block_hash
                    )

                    response = {
                        "jsonrpc": "2.0",
                        "result": result,
                        "id": req.media.get('id')
                    }
                elif method == 'runtime_getMetadataErrors':

                    self.init_request(params)

                    error_list = self.substrate.get_metadata_errors(block_hash=self.block_hash)

                    response = {
                        "jsonrpc": "2.0",
                        "result": error_list,
                        "id": req.media.get('id')
                    }
                elif method == 'runtime_getMetadataError':

                    module_name = self.get_request_param(params)
                    error_name = self.get_request_param(params)

                    self.init_request(params)

                    result = self.substrate.get_metadata_error(
                        module_name=module_name,
                        error_name=error_name,
                        block_hash=self.block_hash
                    )

                    response = {
                        "jsonrpc": "2.0",
                        "result": result,
                        "id": req.media.get('id')
                    }
                elif method == 'runtime_getTypeRegistry':

                    self.init_request(params)

                    result = self.substrate.get_type_registry(block_hash=self.block_hash)

                    if result:
                        result = list(result.values())

                    response = {
                        "jsonrpc": "2.0",
                        "result": result,
                        "id": req.media.get('id')
                    }
                elif method == 'runtime_getType':

                    type_string = self.get_request_param(params)
                    self.init_request(params)

                    response = {
                        "jsonrpc": "2.0",
                        "result": self.substrate.get_type_definition(type_string, block_hash=self.block_hash),
                        "id": req.media.get('id')
                    }
                elif method == 'runtime_addCustomType':

                    type_string = self.get_request_param(params)
                    type_definition = self.get_request_param(params)

                    # Retrieve current custom type registry
                    custom_type_registry = self.cache_region.get('CUSTOM_TYPE_REGISTRY')

                    if not custom_type_registry:
                        custom_type_registry = {
                            'types': {

                            }
                        }

                    custom_type_registry['types'][type_string] = type_definition

                    # TODO Try to decode given type definition

                    # Store updated custom type registry
                    self.cache_region.set('CUSTOM_TYPE_REGISTRY', custom_type_registry)

                    if settings.DEBUG:
                        print('Custom types updated to: ', custom_type_registry)

                    # Update runtime configuration
                    RuntimeConfiguration().update_type_registry(custom_type_registry)

                    response = {
                        "jsonrpc": "2.0",
                        "result": "Type registry updated",
                        "id": req.media.get('id')
                    }

                elif method == 'runtime_setCustomTypes':

                    custom_types = self.get_request_param(params)

                    if type(custom_types) is not dict:
                        raise ValueError('custom types must be in format: {"type_string": "type_definition"}')

                    custom_type_registry = {
                        'types': custom_types
                    }

                    # Store updated custom type registry
                    self.cache_region.set('CUSTOM_TYPE_REGISTRY', custom_type_registry)

                    # Reset runtime configuration
                    RuntimeConfiguration().clear_type_registry()
                    self.init_type_registry(custom_type_registry)

                    if settings.DEBUG:
                        print('Custom types updated to: ', custom_type_registry)

                    response = {
                        "jsonrpc": "2.0",
                        "result": "Type registry updated",
                        "id": req.media.get('id')
                    }
                elif method == 'runtime_resetCustomTypes':

                    custom_type_registry = None

                    # Store updated custom type registry
                    self.cache_region.set('CUSTOM_TYPE_REGISTRY', custom_type_registry)

                    # Reset runtime configuration
                    RuntimeConfiguration().clear_type_registry()
                    self.init_type_registry()

                    if settings.DEBUG:
                        print('Custom types cleared')

                    response = {
                        "jsonrpc": "2.0",
                        "result": "Custom types cleared",
                        "id": req.media.get('id')
                    }
                elif method == 'runtime_removeCustomType':

                    type_string = self.get_request_param(params)

                    # Retrieve current custom type registry
                    custom_type_registry = self.cache_region.get('CUSTOM_TYPE_REGISTRY')

                    if custom_type_registry and type_string in custom_type_registry.get('types', {}):
                        del custom_type_registry['types'][type_string]

                        # Store updated custom type registry
                        self.cache_region.set('CUSTOM_TYPE_REGISTRY', custom_type_registry)

                        # Reset runtime configuration
                        RuntimeConfiguration().clear_type_registry()
                        self.init_type_registry(custom_type_registry)

                        result = '"{}" removed from custom type registry'.format(type_string)

                    else:
                        result = '"{}" not found in custom type registry'.format(type_string)

                    response = {
                        "jsonrpc": "2.0",
                        "result": result,
                        "id": req.media.get('id')
                    }
                elif method == 'runtime_getCustomTypes':

                    custom_type_registry = self.cache_region.get('CUSTOM_TYPE_REGISTRY')

                    if custom_type_registry:
                        result = custom_type_registry.get('types')
                    else:
                        result = {}

                    response = {
                        "jsonrpc": "2.0",
                        "result": result,
                        "id": req.media.get('id')
                    }
                elif method == 'runtime_decodeScale':

                    type_string = self.get_request_param(params)
                    scale_hex_bytes = self.get_request_param(params)

                    self.init_request(params)

                    result = self.substrate.decode_scale(
                        type_string=type_string,
                        scale_bytes=scale_hex_bytes,
                        block_hash=self.block_hash
                    )

                    response = {
                        "jsonrpc": "2.0",
                        "result": result,
                        "id": req.media.get('id')
                    }
                elif method == 'runtime_encodeScale':

                    type_string = self.get_request_param(params)
                    value = self.get_request_param(params)

                    self.init_request(params)

                    result = self.substrate.encode_scale(
                        type_string=type_string,
                        value=value,
                        block_hash=self.block_hash
                    )

                    response = {
                        "jsonrpc": "2.0",
                        "result": result,
                        "id": req.media.get('id')
                    }
                elif method == 'keypair_create':

                    word_count = self.get_request_param(params) or 0
                    crypto_type = int(self.get_request_param(params) or 1)

                    mnemonic = Keypair.generate_mnemonic(word_count)

                    keypair = Keypair.create_from_mnemonic(
                        mnemonic=mnemonic, address_type=settings.SUBSTRATE_ADDRESS_TYPE, crypto_type=crypto_type
                    )

                    response = {
                        "jsonrpc": "2.0",
                        "result": {
                            'ss58_address': keypair.ss58_address,
                            'public_key': keypair.public_key,
                            'private_key': keypair.private_key,
                            'mnemonic': keypair.mnemonic,
                        },
                        "id": req.media.get('id')
                    }
                elif method == 'keypair_inspect':

                    mnemonic = self.get_request_param(params)
                    crypto_type = int(self.get_request_param(params) or 1)

                    keypair = Keypair.create_from_mnemonic(
                        mnemonic=mnemonic, address_type=settings.SUBSTRATE_ADDRESS_TYPE, crypto_type=crypto_type
                    )

                    response = {
                        "jsonrpc": "2.0",
                        "result": {
                            'ss58_address': keypair.ss58_address,
                            'public_key': keypair.public_key,
                            'private_key': keypair.private_key,
                            'mnemonic': keypair.mnemonic,
                        },
                        "id": req.media.get('id')
                    }
                elif method == 'keypair_sign':
                    mnemonic = self.get_request_param(params)
                    data = self.get_request_param(params)
                    crypto_type = int(self.get_request_param(params) or 1)

                    keypair = Keypair.create_from_mnemonic(
                        mnemonic=mnemonic, address_type=settings.SUBSTRATE_ADDRESS_TYPE, crypto_type=crypto_type
                    )
                    signature = keypair.sign(data)

                    response = {
                        "jsonrpc": "2.0",
                        "result": {'signature': signature},
                        "id": req.media.get('id')
                    }

                elif method == 'keypair_verify':
                    account_address = self.get_request_param(params)
                    data = self.get_request_param(params)
                    signature = self.get_request_param(params)
                    crypto_type = int(self.get_request_param(params) or 1)

                    keypair = Keypair(
                        ss58_address=account_address,
                        address_type=settings.SUBSTRATE_ADDRESS_TYPE,
                        crypto_type=crypto_type
                    )
                    result = keypair.verify(data, signature)

                    response = {
                        "jsonrpc": "2.0",
                        "result": {'verified': result},
                        "id": req.media.get('id')
                    }

                elif method == 'rpc_methods':

                    response = self.substrate.rpc_request(method, params)

                    # Add additional implemented method
                    response['result']['methods'] = sorted(response['result']['methods'] + self.methods)

                else:
                    raise NotImplementedError('Method \'{}\' not implemented yet'.format(method))
            except (ValueError, NotImplementedError) as e:
                response = {
                    "error": {
                        "code": -999,
                        "message": str(e)
                    },
                    "id": req.media.get('id')
                }
            except (InvalidScaleTypeValueException, RemainingScaleBytesNotEmptyException) as e:
                response = {
                    "error": {
                        "code": -998,
                        "message": "Decoding error, given SCALE-value or type registry might be invalid "
                    },
                    "id": req.media.get('id')
                }
            resp.media = response
