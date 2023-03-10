import sys
import re
import os
import logging

from datetime import datetime
from zipfile import ZipFile

COMBINDLIST = ['SectigoRSADomainValidationSecureServerCA.crt', 'USERTrustRSAAAACA.crt', 'AAACertificateServices.crt']
zipFiles = [ x for x in sys.argv if re.search(r'(.zip)$', x)]
zipCWD = [ os.path.split(x)[0] for x in zipFiles]
zipDirectories = []
rootLogger=logging.getLogger()
rootLogger.setLevel(logging.INFO)
loggingHandler = logging.FileHandler(datetime.now().strftime('[%Y-%m-%d-%H-%M-%S]')+'SSLCombind.log', 'w', 'utf-8')
rootLogger.addHandler(loggingHandler)

for zipFile in zipFiles:
    try:
        with ZipFile(zipFile, 'r') as zipRef:
            logging.debug('zipRef')
            try:
                rootDirectory = [ x.rstrip('.crt') for x in zipRef.namelist() if re.search('(?<!SectigoRSADomainValidationSecureServerCA)\.crt', x) != None and re.search('(?<!USERTrustRSAAAACA)\.crt', x) != None and re.search('(?<!AAACertificateServices)\.crt',x) != None][0]
                logging.debug('rootDirectory')
                if zipRef.namelist()[0][-1] != '/':
                    if os.path.exists(rootDirectory) == False:
                        os.mkdir(rootDirectory)
                        logging.info('mkdir:{}'.format(rootDirectory))
                    crtList = [rootDirectory+'/'+rootDirectory+'.crt']
                    logging.debug('crtList')
                    for file in zipRef.namelist():
                        if os.path.exists(rootDirectory+'\\'+file) == False:
                            zipRef.extract(file, rootDirectory)
                            logging.info('Extract File: {}'.format(file))
                else:
                    zipRef.extractall()
                    logging.debug('extractall')
                    rootDirectory= zipRef.namelist()[0][:-1]
                    logging.debug('rootDirectory2')
                    crtList = [ x for x in zipRef.namelist() if re.search('(?<!SectigoRSADomainValidationSecureServerCA)\.crt', x) != None and re.search('(?<!USERTrustRSAAAACA)\.crt', x) != None and re.search('(?<!AAACertificateServices)\.crt',x) != None]
                    for file in [x for x in zipRef.namelist() if os.path.isfile(x)]:
                        logging.info('Extract File: {}'.format(file))
                    logging.debug('crtList+ {}{}+/+{}'.format(rootDirectory, rootDirectory, type(COMBINDLIST[0])))
                crtList.extend([ rootDirectory+'/'+x for x in COMBINDLIST])
                logging.debug(crtList)
            except Exception as e:
                logging.error(datetime.now().strftime('%Y-%m-%d-%H-%M-%S')+' 1 '+e)
            try:
                if zipRef.namelist()[0][-1] == '/': 
                    combindPath = [ x for x in zipRef.namelist() if re.search('(?<!SectigoRSADomainValidationSecureServerCA)\.crt', x) != None and re.search('(?<!USERTrustRSAAAACA)\.crt', x) != None and re.search('(?<!AAACertificateServices)\.crt',x) != None][0].split('/')
                    combindPath[-1] = '_'+combindPath[-1]
                    combindPath = '/'.join(combindPath)
                else:
                    combindPath = rootDirectory+'/_'+rootDirectory+'.crt'
                crtHandler = open(combindPath, 'w' if os.path.exists(combindPath) else 'x')
                logging.debug('crtHandler')
                for crt in crtList:
                    crtReader = open(crt, 'r')
                    crtHandler.write(crtReader.read())
                    logging.info('Write {} to {} Success'.format(crt,combindPath))
                    crtReader.close()
                    os.remove(crt)
                    logging.info('Delete {}'.format(crt))
                crtHandler.close()
            except Exception as e:
                logging.error(datetime.now().strftime('%Y-%m-%d-%H-%M-%S')+' 2 '+str(e))
    except Exception as e:
        logging.error(datetime.now().strftime('%Y-%m-%d-%H-%M-%S')+' 3 '+str(e))
