Start-Process "python-2.7.13.amd64.msi" "/qn" -Wait
C:\Python27\python.exe C:\Python27\Scripts\pip.exe install iis-bridge, requests, slackapi
import-module servermanager
C:\Python27\python.exe deploy.py
