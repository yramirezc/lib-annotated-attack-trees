# Creates the input for the CoreNLP parser. 
# Extracts the plain text definitions of CVEs and creates the file list required by CoreNLP as parameter. 

import sys
import os
from handler_json_nvd import HandlerCVEJson

handler = HandlerCVEJson(sys.argv[1], range(2013,2018))
stanford_corenlp_outfolder_name = "stanford-corenlp-processing-nvd-5yr"   # For 2013-2017 experiment
filelistfl = open(os.path.join(sys.argv[1], stanford_corenlp_outfolder_name, "filelist-2011.txt"), 'wt')

for i in range(0, handler.countCVEDescr()):
    
    filename = handler.getID(i) + '.txt'
    filelistfl.write(os.path.join(sys.argv[1], stanford_corenlp_outfolder_name, filename) + '\n')
    
    outfl = open(os.path.join(sys.argv[1], stanford_corenlp_outfolder_name, filename), 'wt')
    outfl.write(handler.getCVEDescrOrd(i))
    outfl.close()
    
filelistfl.close()
