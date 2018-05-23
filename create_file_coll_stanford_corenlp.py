# Creates the input for the CoreNLP parser. 
# Extracts the plain text definitions of CVEs and creates the file list required by CoreNLP as parameter. 

# sys.argv[1]: Work folder, containing the NVD data and within which the output folder will be created
# sys.argv[2]: Name of output folder. The folder path will be sys.argv[1]/sys.argv[2]
# sys.argv[3]...: years to consider from NVD data     

import sys
import os
from handler_json_nvd import HandlerCVEJson

if len(sys.argv) >= 4:

    years = list(int(yr) for yr in sys.argv[3 : len(sys.argv)])
    
    handler = HandlerCVEJson(sys.argv[1], years)
    filelistfl = open(os.path.join(sys.argv[1], sys.argv[2], "filelist.txt"), 'wt')
    
    for i in range(0, handler.countCVEDescr()):
        
        filename = handler.getID(i) + '.txt'
        filelistfl.write(os.path.join(sys.argv[1], sys.argv[2], filename) + '\n')
        
        outfl = open(os.path.join(sys.argv[1], sys.argv[2], filename), 'wt')
        outfl.write(handler.getCVEDescrOrd(i))
        outfl.close()
        
    filelistfl.close()
