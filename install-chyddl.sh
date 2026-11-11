#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
chyddl_bootstrap_dir="$(mktemp -d)"
trap 'rm -rf -- "$chyddl_bootstrap_dir"' EXIT
cat > "$chyddl_bootstrap_dir/update_core.py" <<'CHYDDL_CORE'
"""Pinned public, signed update channel. Standard library only; shared with root helper."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.request import build_opener,HTTPRedirectHandler,Request

BASE='https://raw.githubusercontent.com/chybmaster/chyddl-downloads/'
VERSION=re.compile(r'(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})\Z')
SHA=re.compile('[0-9a-f]{64}\\Z')
KEY=Path(__file__).with_name('update-public-key.txt')
MAX_PACKAGE=512*1024*1024


def version(value):
    if not isinstance(value,str) or not VERSION.fullmatch(value):raise ValueError('Ungültige Updateversion')
    return tuple(map(int,value.split('.')))


def file_info(info,name,limit):
    if (not isinstance(info,dict) or info.get('name')!=name or not SHA.fullmatch(str(info.get('sha256','')))
        or type(info.get('size')) is not int or not 0<info['size']<=limit):raise ValueError('Ungültiger Dateinachweis')


def validate(data):
    if not isinstance(data,dict) or type(data.get('schema')) is not int or data.get('schema')!=1:raise ValueError('Unbekanntes Updateformat')
    version(data.get('version'))
    if not re.fullmatch('[0-9a-f]{40}',str(data.get('source_commit',''))):raise ValueError('Ungültiger Quellnachweis')
    desktop=data.get('desktop');name='chyddl_'+data['version']+'_amd64.deb'
    file_info(desktop,name,MAX_PACKAGE)
    parts=desktop.get('parts')
    if not isinstance(parts,list) or not 1<=len(parts)<=32:raise ValueError('Ungültige Paketteile')
    for n,part in enumerate(parts):file_info(part,name+f'.part{n:02d}',32*1024*1024)
    if sum(p['size'] for p in parts)!=desktop['size']:raise ValueError('Paketgröße stimmt nicht')
    android=data.get('android',{});version(android.get('version'))
    file_info(android,'chyddl-android-'+android['version']+'.apk',32*1024*1024)
    if type(android.get('version_code')) is not int or not 1<=android['version_code']<2100000000:raise ValueError('Ungültige Android-Version')
    if android.get('signer_sha256')!='fb12ecc51545ccb4c0979f13004c003e09b55dbae6d1a8ab8d009898cb1d8ef4':raise ValueError('Android-Signatur stimmt nicht')
    return data


def verify_document(raw,signature,key=KEY):
    if len(raw)>65536 or len(signature)>256:raise ValueError('Update-Nachweis zu groß')
    try:decoded=base64.b64decode(signature,validate=True)
    except ValueError:raise ValueError('Ungültige Update-Signatur') from None
    with tempfile.TemporaryDirectory(prefix='chyddl-verify-') as temporary:
        p=Path(temporary);(p/'data').write_bytes(raw);(p/'signature').write_bytes(decoded)
        check=subprocess.run(['/usr/bin/openssl','dgst','-sha256','-verify',str(key),'-signature',str(p/'signature'),str(p/'data')],capture_output=True,timeout=10)
        if check.returncode:raise ValueError('Update-Signatur ungültig; keine Installation')
    try:return validate(json.loads(raw))
    except (TypeError,KeyError,AttributeError,json.JSONDecodeError):raise ValueError('Ungültiger Update-Nachweis') from None


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ValueError('Update-Weiterleitung verweigert')


def fetch(relative,limit):
    if not re.fullmatch(r'(stable|downloads-v[0-9.]+)/[A-Za-z0-9_.-]+',relative):raise ValueError('Ungültiger Downloadpfad')
    with build_opener(NoRedirect()).open(Request(BASE+relative,headers={'Cache-Control':'no-cache','User-Agent':'chyddl-updater'}),timeout=30) as response:
        raw=response.read(limit+1)
    if len(raw)>limit:raise ValueError('Download überschreitet die erlaubte Größe')
    return raw


def channel():
    raw=fetch('stable/update.json',65536);sig=fetch('stable/update.sig',256)
    return verify_document(raw,sig),raw,sig


def atomic(path,raw):
    descriptor,name=tempfile.mkstemp(prefix='.update-',dir=path.parent)
    try:
        with os.fdopen(descriptor,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)
    finally:Path(name).unlink(missing_ok=True)


def prepare(directory):
    data,raw,sig=channel();directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    stage=directory/data['version'];stage.mkdir(mode=0o700,exist_ok=True)
    if (stage.is_symlink() or directory.is_symlink() or directory.resolve()!=directory.absolute()
        or directory.stat().st_uid!=os.getuid() or stage.stat().st_uid!=os.getuid()):raise ValueError('Unsicherer Updateordner')
    directory.chmod(0o700);stage.chmod(0o700)
    target=stage/data['desktop']['name']
    if not target.is_symlink() and target.is_file() and target.stat().st_size==data['desktop']['size']:
        with target.open('rb') as stream:cached=digest(stream)
        if cached==data['desktop']['sha256']:
            atomic(stage/'update.json',raw);atomic(stage/'update.sig',sig)
            return data,stage
    descriptor,name=tempfile.mkstemp(prefix='.package-',dir=stage);temporary=Path(name)
    try:
        with os.fdopen(descriptor,'wb') as stream:
            for part in data['desktop']['parts']:
                content=fetch('downloads-v'+data['version']+'/'+part['name'],part['size'])
                if len(content)!=part['size'] or hashlib.sha256(content).hexdigest()!=part['sha256']:raise ValueError('Paketteil beschädigt')
                stream.write(content)
            stream.flush();os.fsync(stream.fileno())
        with temporary.open('rb') as stream:actual=hashlib.file_digest(stream,'sha256').hexdigest() if hasattr(hashlib,'file_digest') else digest(stream)
        if actual!=data['desktop']['sha256']:raise ValueError('Paket beschädigt')
        os.replace(temporary,target);atomic(stage/'update.json',raw);atomic(stage/'update.sig',sig)
    finally:temporary.unlink(missing_ok=True)
    return data,stage


def digest(stream):
    value=hashlib.sha256()
    for content in iter(lambda:stream.read(1024*1024),b''):value.update(content)
    return value.hexdigest()
CHYDDL_CORE
cat > "$chyddl_bootstrap_dir/update-public-key.txt" <<'CHYDDL_PUBLIC_KEY'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYlf08h8KP41/VtNyS0froIVTkSZF
CWUp/8sbPH6aFbDWsrlPDrpr6C09l+wOtsUhOIf8eUmoSl+Z8tNHPkgslg==
-----END PUBLIC KEY-----
CHYDDL_PUBLIC_KEY
cat > "$chyddl_bootstrap_dir/install.py" <<'CHYDDL_INSTALL'
import os,sys,subprocess,tempfile,shutil
from pathlib import Path
import update_core as core
VERSION="14.9.37"
def pinned():
 raw=core.fetch('downloads-v'+VERSION+'/update.json',65536);sig=core.fetch('downloads-v'+VERSION+'/update.sig',256)
 data=core.verify_document(raw,sig)
 if data['version']!=VERSION:raise ValueError('Version stimmt nicht')
 return data,raw,sig
core.channel=pinned
args=sys.argv[1:]
if args and (len(args)!=2 or args[0]!='--download-only'):raise SystemExit('Hilfe: install-chyddl.sh [--download-only ORDNER]')
if subprocess.check_output(['dpkg','--print-architecture'],text=True).strip()!='amd64':raise SystemExit('Ubuntu amd64 erforderlich')
with tempfile.TemporaryDirectory(prefix='chyddl-install-') as temp:
 data,stage=core.prepare(Path(temp));package=stage/data['desktop']['name']
 for field,wanted in [('Package','chyddl'),('Version',VERSION),('Architecture','amd64')]:
  if subprocess.check_output(['dpkg-deb','-f',str(package),field],text=True).strip()!=wanted:raise SystemExit('Paketidentität stimmt nicht')
 if args:
  destination=Path(args[1]);destination.mkdir(parents=True,exist_ok=True)
  target=destination/package.name
  fd,name=tempfile.mkstemp(dir=destination,prefix='.verified-');os.close(fd)
  try:shutil.copyfile(package,name);os.link(name,target)
  finally:Path(name).unlink(missing_ok=True)
  print('Geprüfter Installer: '+str(target))
 else:
  if Path('/usr/bin/chyddl-safe-stop').is_file():
   from urllib.request import build_opener,ProxyHandler
   try:
    with build_opener(ProxyHandler({})).open('http://127.0.0.1:8765/static/chyddl-version.json',timeout=2) as stream:stream.read(4096)
   except OSError:pass
   else:
    owned=False
    for table in ('/proc/net/tcp','/proc/net/tcp6'):
     for line in Path(table).read_text().splitlines()[1:]:
      fields=line.split()
      if fields[3]=='0A' and int(fields[1].rsplit(':',1)[1],16)==8765:
       if int(fields[7])!=os.getuid():raise SystemExit('Der lokale Dienst gehört einem anderen Benutzer. Keine Anmeldung oder Installation ausgeführt.')
       owned=True
    if not owned:raise SystemExit('Dienstbesitzer konnte nicht bestätigt werden. App schließen und erneut versuchen.')
    extracted=Path(temp)/'stop-helper'
    subprocess.run(['dpkg-deb','--extract',str(package),str(extracted)],check=True)
    result=subprocess.run([sys.executable,'-I',str(extracted/'opt/chyddl/safe-stop.py')],stdin=subprocess.DEVNULL)
    if result.returncode:raise SystemExit('Sicheres Beenden nicht bestätigt. App schließen und Installation wiederholen; kein chyddl-Kennwort erforderlich.')
  Path(temp).chmod(0o755);stage.chmod(0o755);package.chmod(0o644)
  subprocess.run(([] if os.getuid()==0 else ['sudo','--'])+['apt-get','install',str(package)],check=True)
  print('chyddl installiert. Künftige signierte Updates laufen direkt in der App.')
CHYDDL_INSTALL
python3 "$chyddl_bootstrap_dir/install.py" "$@"
