#!/usr/bin/env python3

import logging
import asyncio
import json
import time
import datetime
import simplejson
from decimal import Decimal
from json import JSONDecodeError
from multiprocessing import Process
from signal import signal, SIGINT
from threading import Thread
from aiohttp import web
from aiorpcx import connect_rs, timeout_after
from kubernetes import client, config
from kubernetes.config import ConfigException


logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
    handlers=[
        logging.FileHandler("debug.log"),
        logging.StreamHandler()
    ])

logger = logging.getLogger(__name__)
# namespace = environ.get('NAMESPACE')
namespace = 'cc-backend'
coins = {}
allowed = ["BLOCK", "BTC", "BCH", "LTC", "DASH", "DOGE", "DGB", "PIVX", "RVN", "SYS", "TZC", "XSN"]

try:
    config.load_incluster_config()
except ConfigException:
    config.load_kube_config()

v1 = client.CoreV1Api()

ret = v1.list_namespaced_service(namespace, label_selector="app=utxoplugin", watch=False)
for item in ret.items:
    logger.info(item)
    currency = item.metadata.labels['currency']

    if currency not in allowed:
        continue

    host = "{}.{}.svc.cluster.local".format(item.metadata.name, namespace)

    coins[currency] = {
        'host': host,
        'port': 8000
    }

logger.info('ACTIVE UTXOPLUGINS:\n{}'.format(coins))

OS_ERROR = -1
OTHER_EXCEPTION = -2


class TCPSocket:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.session = None

    async def connect(self):
        try:
            self.session = await connect_rs(self.host, self.port).__aenter__()
            self.session.transport._framer.max_size = 0
        except Exception as e:
            logger.error("[client] ERROR: Error connecting!", e)
            self.session = None

    async def reconnect_if_closing(self):
        if self.session is None or self.session.is_closing():
            await self.connect()

    async def send_message(self, command, message, timeout=30):
        await self.reconnect_if_closing()

        if self.session is None:
            return OTHER_EXCEPTION

        try:
            async with timeout_after(timeout):
                return await self.session.send_request(command, message)
        except OSError:
            logger.error(
                "[client] ERROR: Could not connect! Is the Electrum X server running on port " + str(self.port) + "?")
            return OS_ERROR
        except Exception as e:
            logger.error("[client] ERROR: Error sending request!", e)
            return OTHER_EXCEPTION

    async def send_batch(self, command, message=None, timeout=30):
        await self.reconnect_if_closing()

        if message is None or type(message) != list:
            return OTHER_EXCEPTION

        try:
            async with timeout_after(timeout):
                async with self.session.send_batch() as batch:
                    for msg in message:
                        batch.add_request(command, [msg])

                return batch.results
        except OSError:
            logger.error(
                "[client] ERROR: Could not connect! Is the Electrum X server running on port " + str(self.port) + "?")
            return OS_ERROR
        except Exception as e:
            logger.error("[client] ERROR: Error sending request!", e)
            return OTHER_EXCEPTION


class HeartbeatThread(Thread):
    def __init__(self):
        super().__init__()

    def run(self):
        super().run()
        global heartbeat_running
        if heartbeat_running:
            self.join()
            return

        heartbeat_running = True

        asyncio.set_event_loop(asyncio.new_event_loop())
        for coin in coins.keys():
            get_info(coin, True)

        while heartbeat_running:
            for coin in coins.keys():
                get_info(coin)
            time.sleep(2)

    def stop(self):
        global heartbeat_running
        heartbeat_running = False


heartbeat_running = False
heartbeat_thread: HeartbeatThread

app_process: Process

routes = web.RouteTableDef()
aio_app = web.Application()


def TimestampMillisec64():
    return int((datetime.datetime.utcnow() - datetime.datetime(1970, 1, 1)).total_seconds() * 1000)


def parse_response(response: list):
    refined_result = []

    logger.info("[server] response: " + str(response))
    try:
        for utxos in response:
            for item in utxos:
                refined_result.append({
                    "address": item['address'],
                    "txhash": item['tx_hash'],
                    "vout": int(item['tx_pos']),
                    "block_number": int(item['height']),
                    "value": float(item['value']) / 100000000.0
                })

        return refined_result
    except TypeError as e:  # we should think about proper error handling instead of returning None
        logger.info("[ERROR] error: " + str(e))
        return None


async def makesession():
    return


def get_info(currency, initial=False):
    if currency not in coins.keys():
        print("[client] ERROR: Attempted to get info for unsupported coin " + currency)
        return None

    host = coins[currency]['host']
    port = coins[currency]['port']

    result = None

    async def send_request():
        try:
            async with timeout_after(15):
                async with connect_rs(host, port) as session:
                    session.transport._framer.max_size = 0
                    global result
                    result = await session.send_request("getinfo")

                    if initial:
                        print("[heartbeat] Initial heartbeat for " + currency + ":")
                        print("\tPID: " + str(result["pid"]))
                        print("\tServer version: " + result["version"])
                    else:
                        print("[heartbeat] " + currency + ": ")
                        print("\tHeight (DB/Daemon): " + str(result["db_height"]) + " / " + str(
                            result["daemon_height"]) + " blocks")
                        print("\tuptime " + result["uptime"])

                    return result
        except OSError:
            print("[client] ERROR: Could not connect! Is the Electrum X server running on port " + str(port) + "?")
            return None
        except Exception as e:
            print("[client] ERROR: Error sending request!")
            return None


async def getutxos(params):
    currency = params[0]
    try:
        addresses = json.loads(params[1])
    except TypeError as e:
        addresses = params[1]
    except JSONDecodeError as e:
        addresses = params[1]

    if type(addresses) == str:
        addresses = addresses.split(',')

    if len(addresses) == 0 or type(addresses) != list:
        return None

    timestart = TimestampMillisec64()
    logger.info("[server] " + str(timestart) + " " + "xrmgetutxos: " + currency + " - " + str(addresses))

    if currency not in coins.keys():
        logger.warning("[client] ERROR: Attempted to get UTXOs from unsupported coin " + currency)
        return None

    socket = coins[currency]['socket']

    data = await socket.send_batch("blockchain.address.listunspent", addresses, timeout=30)

    if data == OS_ERROR or data == OTHER_EXCEPTION:
        return None

    res = {"utxos": parse_response(data)}

    if res is None or res['utxos'] is None:
        logging.info("[server] getutxos failed for coin: " + currency)
        return None

    logger.debug("DEBUG MESSAGE: ", res)
    logger.info("[server-end getutxos] completion time: {}ms".format(TimestampMillisec64() - timestart))

    return json.dumps(res)


async def getrawtransaction(params):
    currency = params[0]
    txid = params[1]
    verbose = False

    if len(params) == 3:
        v = params[2]
        if any(x == v for x in [True, 'true', 'True', '1', 1]):
            verbose = True
        else:
            verbose = False

    logger.info("[server] xrmgetrawtransaction: " + currency + " - " + str(txid))

    if currency not in coins.keys():
        logger.warning("[client] ERROR: Attempted to get raw transaction from unsupported coin " + currency)
        return None

    socket = coins[currency]['socket']
    res = {'result': None, 'error': None}

    data = await socket.send_message("blockchain.transaction.get", [txid, verbose], timeout=30)

    if data == OS_ERROR or data == OTHER_EXCEPTION:
        logger.error("[server] ERROR: Error during getrawtranscation grabbing!")
        res['error'] = -5
    else:
        res['result'] = data

    logger.debug("DEBUG MESSAGE: ", res)

    return json.dumps(res)


async def getrawmempool(params):
    currency = params[0]
    verbose = False

    if len(params) == 2:
        v = params[1]
        if any(x == v for x in [True, 'true', 'True', '1', 1]):
            verbose = True
        else:
            verbose = False

    logger.info("[server] xrmgetrawmempool: " + currency + " - " + str(verbose))

    if currency not in coins.keys():
        logger.warning("[client] ERROR: Attempted to getmemrawpool from unsupported coin " + currency)
        return None

    socket = coins[currency]['socket']
    res = {'result': None, 'error': None}

    data = await socket.send_message("getrawmempool", [verbose], timeout=30)

    if data == OS_ERROR or data == OTHER_EXCEPTION:
        logger.error("[server] ERROR: Error during getrawmempool grabbing!")
        res['error'] = -1
    else:
        res['result'] = data

    logger.debug("DEBUG MESSAGE: ", res)

    return json.dumps(res)


async def getblockcount(params):
    currency = params[0]

    logger.info("[server] xrmgetblockcount: " + currency)

    if currency not in coins.keys():
        logger.warning("[client] ERROR: Attempted to get blockcount from unsupported coin " + currency)
        return None

    socket = coins[currency]['socket']
    res = {'result': None, 'error': None}

    data = await socket.send_message("getblockcount", (), timeout=30)

    if data == OS_ERROR or data == OTHER_EXCEPTION:
        logger.error("[server] ERROR: Error during getblockcount grabbing!")
        res['error'] = -1
    else:
        res['result'] = data

    logger.debug("DEBUG MESSAGE: ", res)

    return json.dumps(res)


async def sendrawtransaction(params):
    currency = params[0]
    rawtx = params[1]

    logger.info("[server] xrmsendrawtransaction: " + currency)

    if currency not in coins.keys():
        logger.warning("[client] ERROR: Attempted to sendtx to unsupported coin " + currency)
        return None

    socket = coins[currency]['socket']
    res = {'result': None, 'error': None}

    data = await socket.send_message("blockchain.transaction.broadcast", [rawtx], timeout=30)

    if data == OS_ERROR:
        logger.error("[server] ERROR: OSError during sendrawtransaction!")
        res['error'] = -1
    elif data == OTHER_EXCEPTION:
        logger.error("[server] ERROR: -25 during sendrawtransaction!")
        res['error'] = -25
    else:
        res['result'] = data

    logger.debug("DEBUG MESSAGE: ", res)

    return json.dumps(res)


async def gettransaction(params):
    currency = params[0]
    txid = params[1]
    verbose = True

    logger.info("[server] xrmgettransaction: " + currency + " - " + str(txid))

    if currency not in coins.keys():
        logger.warning("[client] ERROR: Attempted to get transaction from unsupported coin " + currency)
        return None

    socket = coins[currency]['socket']
    res = {'result': None, 'error': None}

    data = await socket.send_message("blockchain.transaction.get", [txid, verbose], timeout=30)

    if data == OS_ERROR or data == OTHER_EXCEPTION:
        logger.error("[server] ERROR: Error during getblock grabbing!")
        res['error'] = -1
    else:
        res['result'] = data

    logger.debug("DEBUG MESSAGE: ", res)

    return json.dumps(res)


async def getblock(params):
    currency = params[0]
    hex_hash = params[1]
    verbose = False

    if len(params) == 3:
        v = params[2]
        if any(x == v for x in [True, 'true', 'True', '1', 1]):
            verbose = True
        else:
            verbose = False

    logger.info("[server] xrmgetblock: " + currency + " - " + str(hex_hash))

    if currency not in coins.keys():
        logger.warning("[client] ERROR: Attempted to get block from unsupported coin " + currency)
        return None

    socket = coins[currency]['socket']
    res = {'result': None, 'error': None}

    data = await socket.send_message("getblock", [hex_hash, verbose], timeout=30)

    if data == OS_ERROR or data == OTHER_EXCEPTION:
        logger.error("[server] ERROR: Error during getblock grabbing!")
        res['error'] = -1
    else:
        res['result'] = data

    logger.debug("DEBUG MESSAGE: ", res)

    return json.dumps(res)


async def getblockhash(params):
    currency = params[0]
    height = params[1]

    logger.info("[server] xrmgetblockhash: " + currency + " - " + str(height))

    if currency not in coins.keys():
        logger.warning("[client] ERROR: Attempted to get block hash from unsupported coin " + currency)
        return None

    socket = coins[currency]['socket']
    res = {'result': None, 'error': None}

    data = await socket.send_message("getblockhash", [int(height)], timeout=30)

    if data == OS_ERROR or data == OTHER_EXCEPTION:
        logger.error("[server] ERROR: Error during getblockhash grabbing!")
        res['error'] = -1
    else:
        res['result'] = data

    logger.debug("DEBUG MESSAGE: ", res)

    return json.dumps(res)


async def getbalance(params):
    currency = params[0]
    address = params[1]

    logger.info("[server] xrmgetbalance: " + currency + " - " + str(address))

    if currency not in coins.keys():
        logger.warning("[client] ERROR: Attempted to get balance from unsupported coin " + currency)
        return None

    socket = coins[currency]['socket']
    res = {'result': None, 'error': None}

    data = await socket.send_message("blockchain.address.get_balance", [str(address)], timeout=30)

    if data == OS_ERROR or data == OTHER_EXCEPTION:
        logger.error("[server] ERROR: Error during getbalance grabbing!")
        res['error'] = -1
    else:
        if data['confirmed'] > 0:
            data['confirmed'] = float(data['confirmed']) / 100000000.0

        if data['unconfirmed'] > 0:
            data['unconfirmed'] = float(data['unconfirmed']) / 100000000.0

        res['result'] = data

    logger.debug("DEBUG MESSAGE: ", res)

    return json.dumps(res)


async def ping():
    logger.info("[server] ping")

    res = {'result': 1, 'error': None}

    return json.dumps(res)


async def plugin_block_heights():
    heights = {}
    for coin in coins:
        logger.info("[server] getting block_count for coin: " + coin)
        data = await get_block_count(coin)

        if data is None:
            heights[coin] = None
            continue

        logger.info("[server] finished block_count, block# " + str(data))
        heights[coin] = data

    res = {'result': heights, 'error': None}

    return json.dumps(res)


async def plugin_tx_fees():
    fees = {}
    for coin in coins:
        logger.info("[server] getting fees for coin: " + coin)
        data = await get_plugin_fees(coin)

        if data is None:
            fees[coin] = None
            continue

        fees[coin] = Decimal('{:.8f}'.format(data))

    res = {'result': fees, 'error': None}

    return simplejson.dumps(res)


async def get_block_count(currency):
    if currency not in coins.keys():
        logger.warning("[client] ERROR: Attempted to get info for unsupported coin " + currency)
        return None

    socket = coins[currency]['socket']

    res = await socket.send_message("getblockcount", (), timeout=5)

    if res == OS_ERROR or res == OTHER_EXCEPTION:
        return None

    return res


async def get_plugin_fees(currency):
    if currency not in coins.keys():
        logger.warning("[client] ERROR: Attempted to get info for unsupported coin " + currency)
        return None

    socket = coins[currency]['socket']

    res = await socket.send_message("blockchain.relayfee", (), timeout=5)

    if res == OS_ERROR or res == OTHER_EXCEPTION:
        return None

    return res


async def gethistory(params):
    currency = params[0]
    try:
        addresses = json.loads(params[1])
    except TypeError as e:
        addresses = params[1]
    except JSONDecodeError as e:
        addresses = params[1]

    if type(addresses) == str:
        addresses = addresses.split(',')

    if len(addresses) == 0 or type(addresses) != list:
        return None

    timestart = TimestampMillisec64()
    logger.info("[server] " + str(timestart) + " " + "xrmgethistory: " + currency + " - " + str(addresses))

    if currency not in coins.keys():
        logger.warning("[client] ERROR: Attempted to get history from unsupported coin " + currency)
        return None

    socket = coins[currency]['socket']

    res = await socket.send_batch("gethistory", addresses, timeout=60)

    if res is None or res == OS_ERROR or res == OTHER_EXCEPTION:
        logging.info("[server] gethistory failed for coin: " + currency)

        return None
        
    if len(res) == 1:
        res = res[0]

    logger.debug("DEBUG MESSAGE: ", res)
    logger.info("[server-end gethistory] completion time: {}ms".format(TimestampMillisec64() - timestart))

    return json.dumps(res)


async def switchcase(requestjson):
    switcher = {
        'getutxos': getutxos(requestjson['params']),
        'getrawtransaction': getrawtransaction(requestjson['params']),
        'getrawmempool': getrawmempool(requestjson['params']),
        'getblockcount': getblockcount(requestjson['params']),
        'sendrawtransaction': sendrawtransaction(requestjson['params']),
        'gettransaction': gettransaction(requestjson['params']),
        'getblock': getblock(requestjson['params']),
        'getblockhash': getblockhash(requestjson['params']),
        'heights': plugin_block_heights(),
        'fees': plugin_tx_fees(),
        'getbalance': getbalance(requestjson['params']),
        'gethistory': gethistory(requestjson['params']),
        'ping': ping()
    }

    return await switcher.get(requestjson['method'], ping)


@routes.post("/")
async def handle(request):
    return web.Response(text=await switchcase(await request.json()))


@routes.get("/height")
async def get_heights(request):
    return web.Response(text=await plugin_block_heights())


@routes.get("/fees")
async def get_fees(request):
    return web.Response(text=await plugin_tx_fees())


def run_app(port: int):
    global heartbeat_thread, app_process, aio_app

    aio_app.add_routes(routes)

    app_process = Process(target=web.run_app, kwargs={
        "app": aio_app,
        "host": "0.0.0.0",
        "port": port
    })

    print("[server] Starting server.")
    app_process.start()

    heartbeat_thread = HeartbeatThread()
    heartbeat_thread.start()


def sigint_handler(sig, frame):
    print("[adapter] Caught SIGINT. Shutting down heartbeat thread and server.")
    global heartbeat_thread, app_process
    if heartbeat_thread is not None:
        heartbeat_thread.stop()
        heartbeat_thread.join()
        print("[adapter] Shut down heartbeat thread.")
    else:
        print("[adapter] Heartbeat thread is already down.")

        if app_process is not None and app_process.is_alive():
            aio_app.shutdown()
            app_process.terminate()
            app_process.join()
            print("[adapter] Shut down server. Exiting.")
        else:
            print("[adapter] Server is already down. Exiting.")

        print("Awaiting thread join.")


def main():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    for currency in coins:
        host = coins[currency]['host']
        port = coins[currency]['port']

        socket = TCPSocket(host, port + 1000)
        loop.run_until_complete(socket.connect())

        coins[currency]['socket'] = socket

        print("[adapter] Registered host " + host + " port " + str(port) + " for coin " + currency)

    print("[adapter] Have " + str(len(coins)) + " coin/port pair(s).")
    print("[server] Starting RPC server on port 5000.")
    run_app(5000)
    signal(SIGINT, sigint_handler)


if __name__ == '__main__':
    main()

aio_app.add_routes(routes)
app = aio_app

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
