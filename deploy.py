# -*- coding: utf-8 -*-
from __future__ import print_function
from zipfile import ZipFile
from slackapi.integrations import IncomingWebHook
import subprocess as sp
import iis_bridge.pool as pool
import iis_bridge.site as site
import urllib
import logging
import requests
import socket


logging.basicConfig(format='%(asctime)s | %(levelname)s | %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filemode='w',
                    filename="out.log", level=logging.DEBUG)

logging.info('Start Script on host %s...' % socket.gethostname())


def add_roles(roles='Web-Asp-Net45'):
    print('Check and install server roles......')
    try:
        sp.check_call('powershell.exe Add-WindowsFeature -name %s -Verbose' % roles)
    except Exception:
        logging.error('Object: %s | failed to create a role' % add_roles.func_name)
        print('Failed to create a role')
    else:
        logging.info('Object: %s | add roles complete' % add_roles.func_name)
        print('Add roles complete!')


pool_n = 'bratishka'


def create_pool(pool_name=pool_n, runtime_version="4.0", pipeline_mode="Integrated"):
    if not pool.exists(pool_name):
        try:
            pool.create(pool_name, runtime_version, pipeline_mode)
            logging.info('Object: %s | create pool complete' % create_pool.func_name)
            print('Pool "%s" created' % pool_name)
        except Exception:
            logging.error('Object: %s | failed to create a pool' % create_pool.func_name)
            print('Failed to create a pool!')
    else:
        logging.warning('Object: %s | failed to create a pool, '
                      'pool name exists! Select a different name!' % create_pool.func_name)
        print('"%s" pool name exists!\nSelect a different name!' % pool_name)


def create_site(site_name='DevOps', port=8080, app_dir=r"C:\inetpub\wwwroot\DevOpsTaskJunior-master", pool_name=pool_n):
    if not site.exists(site_name):
        try:
            site.create(site_name, port, app_dir, pool_name)
            logging.info('Object: %s | create site complete' % create_site.func_name)
            print('Site "%s" created' % site_name)
        except Exception:
            logging.error('Object: %s | failed to create a site' % create_site.func_name)
            print('Failed to create a site!')
            print(Exception.message)
    else:
        logging.warning('Object: %s | failed to create a site, '
                      'site name exists! Select a different name!' % create_site.func_name)
        print('"%s" site name exists!\nSelect a different name!' % site_name)


def get_files():
    try:
        print('Download files in C:\inetpub\wwwroot ...')
        urllib.urlretrieve('https://github.com/TargetProcess/DevOpsTaskJunior/archive/master.zip',
                           r"C:\inetpub\wwwroot\master.zip")
    except Exception:
        logging.error('Object: %s | download failed!' % urllib.urlretrieve.func_name)
        print('Download failed!')
    else:
        logging.info('Object: %s | download .zip completed!' % urllib.urlretrieve.func_name)
        print('Download completed')
    try:
        print('Extract files in C:\inetpub\wwwroot ...')
        zipfile = ZipFile(r"C:\\inetpub\\wwwroot\\master.zip")
        zipfile.extractall(r"C:\\inetpub\\wwwroot\\")
    except Exception:
        logging.error('Object: Zip | extract files failed!')
        print('Extract files failed!')
    else:
        logging.info('Object: Zip | extract files complete!')
        print('Extract files complete')


def set_permission():
    try:
        sp.check_call("powershell.exe $acl = Get-Acl C:\\inetpub\\wwwroot\\DevOpsTaskJunior-master;"
                      "$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule"
                      "('BUILTIN\IIS_IUSRS','FullControl','ContainerInherit,ObjectInherit','None','Allow');"
                      "$acl.SetAccessRule($AccessRule); $acl | Set-Acl C:\\inetpub\\wwwroot\\DevOpsTaskJunior-master")
    except Exception:
        logging.error('Object: %s | set permissions failed!' % set_permission.func_name)
        print('Set permissions failed!')
    else:
        logging.info('Object: %s | set permissions success!' % set_permission.func_name)
        print('Set permissions success')


def check_connect():
    try:
        response = requests.get('http://localhost:8080/')
        response.raise_for_status()
    except requests.ConnectionError:
        logging.error('Object: %s | Connection to http://localhost:8080 failed!' % check_connect.func_name)
        print('Connection to http://localhost:8080 failed!')
        raw_input('See log file in script folder, press [ENTER] for exit')
    except requests.HTTPError as err:
        logging.error('Object: %s | Error message: %s | HTTP error code %s!' %
                      (check_connect.func_name, err.message, err.response.status_code))
        print('Oops. HTTP Error occured')
        print(err.message)
        raw_input('See log file in script folder, press [ENTER] for exit')
    except requests.RequestException:
        logging.error('Object: %s | Error occured' % check_connect.func_name)
        print('Error occured!')
        raw_input('See log file in script folder, press [ENTER] for exit')
    else:
        if response.status_code == 200:
            logging.info('Object: %s | Application is works | HTTP code %s' %
                         (check_connect.func_name, response.status_code))
            hook = IncomingWebHook(webhook_url=
                                   "https://hooks.slack.com/services/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")
            answer = (hook.send_message(text='Братишки, я вам покушать принес', username='Пахом', icon_emoji=':shit:'))
            if answer.status_code == 200:
                logging.info('Object: webhook | Message was sent to Slack')
                print('Message was sent to Slack')
            else:
                logging.error('Object: webhook | Error sending message to Slack')
            logging.info('Application is works on http://localhost:8080')
            raw_input('Application is works, press [ENTER] for exit')


if __name__ == "__main__":
    add_roles()
    create_pool()
    create_site()
    get_files()     # закоментить для проверки исправленного конфига
    set_permission()
    check_connect()
