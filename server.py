# Install uvloop
try:
	import uvloop
	uvloop.install()
except ImportError:
	print("Couldn't install uvloop, falling back to the slower asyncio event loop")

import rapidjson as json
import os
import logging
import ipaddress
import argparse
import asyncio
from logging.handlers import TimedRotatingFileHandler, WatchedFileHandler
from aiohttp import web, ClientSession, log
from dotenv import load_dotenv
load_dotenv()


# Configuration arguments

parser = argparse.ArgumentParser(description="Discord Captcha Server")
parser.add_argument('--host', type=str,
                    help='Host to listen on (e.g. 127.0.0.1)', default='127.0.0.1')
parser.add_argument('--path', type=str,
                    help='(Optional) Path to run application on (for unix socket, e.g. /tmp/natriumapp.sock', default=None)
parser.add_argument('-p', '--port', type=int,
                    help='Port to listen on', default=8008)
parser.add_argument('--log-file', type=str,
                    help='Log file location', default='discord_captcha.log')
options = parser.parse_args()

recaptcha_secret = os.getenv("RECAPTCHA_SECRET", None)
discord_channel_id = os.getenv("DISCORD_CHANNEL_ID", None)
discord_token = os.getenv("DISCORD_TOKEN", None)

try:
    listen_host = str(ipaddress.ip_address(options.host))
    listen_port = int(options.port)
    log_file = options.log_file
    app_path = options.path
    if app_path is None:
        server_desc = f'on {listen_host} port {listen_port}'
    else:
        server_desc = f'on {app_path}'
    print(f'Starting Discord Catpcha Server {server_desc}')
except Exception:
    parser.print_help()
    exit(0)


def get_request_ip(r: web.Request) -> str:
    host = r.headers.get('X-FORWARDED-FOR', None)
    if host is None:
        peername = r.transport.get_extra_info('peername')
        if peername is not None:
            host, _ = peername
    return host


async def getInvite(request: web.Request):
    """Generate an invite"""
    # Get captcha param
    try:
        captcha = request.rel_url.query['captcha']
        if captcha is None:
            raise KeyError
    except KeyError:
        return web.HTTPUnauthorized(
            reason='No captcha specified.'
        )
    # Verify catpcha
    request_json = {
        'secret': recaptcha_secret,
        'response': captcha,
        'remoteip': get_request_ip(request)
    }
    try:
        async with ClientSession(json_serialize=json.dumps) as session:
            async with session.post('https://www.google.com/recaptcha/api/siteverify', json=request_json, timeout=30) as resp:
                if resp.status != 200:
                    err_msg = 'Captcha not valid. Please retry.'
                    resp_json = await resp.json(loads=json.loads)
                    if 'error_codes' in resp_json:
                        err_msg += 'Errors: ' + \
                            ', '.join(resp_json['error_codes'])
                    return web.HTTPUnauthorized(
                        reason=err_msg
                    )
    except Exception:
        log.server_logger.exception()
        return web.HTTPInternalServerError(
            reason='Error occured verifying catptcha'
        )

    discordParams = {
        'max_uses': 1,
        'max_age': 600,  # 10 minutes
        'unique': True,
    }
    headers = {
        'Authorization': f'Bot {discord_token}'
    }
    try:
        async with ClientSession(json_serialize=json.dumps) as session:
            async with session.post(f'https://discordapp.com/api/channels/{discord_channel_id}/invites', headers=headers, json=discordParams, timeout=30) as resp:
                resp_json = await resp.json(loads=json.loads)
                if resp.status < 200 or resp.status >= 400:
                    return web.HTTPInternalServerError(
                        reason=f'Discord returned error {resp.status} {json.dumps(resp_json)}'
                    )
                elif 'code' not in resp_json:
                    return web.HTTPInternalServerError(
                        reason="No invite code received from discord"
                    )
                invite_code = resp_json['code']
    except Exception:
        log.server_logger.exception()
        return web.HTTPInternalServerError(
            reason='Error occured requesting invite from discord'
        )
    return web.HTTPFound(location=f'https://discord.gg/{invite_code}')

loop = asyncio.get_event_loop()


async def init_app():
    """ Initialize the main application instance and return it"""
    # Setup logger
    root = logging.getLogger('aiohttp.server')
    logging.basicConfig(level=logging.INFO)
    handler = WatchedFileHandler(log_file)
    formatter = logging.Formatter(
        "%(asctime)s;%(levelname)s;%(message)s", "%Y-%m-%d %H:%M:%S %z")
    handler.setFormatter(formatter)
    root.addHandler(handler)
    root.addHandler(TimedRotatingFileHandler(
        log_file, when="d", interval=1, backupCount=100))

    app = web.Application(middlewares=[web.normalize_path_middleware()])
    app.add_routes([web.get('/getInvite', getInvite)])  # All requests

    return app

app = loop.run_until_complete(init_app())


def main():
    """Main application loop"""
    # Start web server
    async def start():
        runner = web.AppRunner(app)
        await runner.setup()
        if app_path is not None:
            site = web.UnixSite(runner, app_path)
        else:
            site = web.TCPSite(runner, listen_host, listen_port)
        await site.start()

    async def end():
        await app.shutdown()

    loop.run_until_complete(start())

    # Main program
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        loop.run_until_complete(end())

    loop.close()


if __name__ == "__main__":
    main()
